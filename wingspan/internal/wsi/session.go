package wsi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dtrace"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
)

// Session is the internal representation of a session.
type Session[
	PktIn any, PktOut wspacket.OutboundPacket,
	DeltaIn, DeltaOut any,
] struct {
	log *slog.Logger

	tracer dtrace.Tracer

	// We store the full header only once on the session
	// and then reuse it for every outbound worker.
	header []byte

	// The session ID is a subslice into header,
	// and it should be treated as read-only.
	// This is only used for logging and tracing.
	sessionID []byte

	state  wspacket.CentralState[PktIn, PktOut, DeltaIn, DeltaOut]
	deltas *dpubsub.Stream[DeltaOut]

	acceptStreamRequests chan acceptStreamRequest
	inboundDeltaArrivals chan inboundDeltaArrival[DeltaIn]
}

// acceptStreamRequest contains the details necessary
// to add an inbound stream to the [Session].
type acceptStreamRequest struct {
	Conn   dconn.Conn
	Stream dquic.ReceiveStream
	Resp   chan struct{}
}

// inboundDeltaArrival is the value sent by an [InboundWorker]
// to the [Session], after parsing and processing a packet from the peer.
type inboundDeltaArrival[DeltaIn any] struct {
	Delta DeltaIn
	Resp  chan<- inboundDeltaResult
}

// inboundDeltaResult is the value the [Session] reports
// back to an [InboundWorker], when the worker
// receives a packet, parses it, and reports it back to central state.
type inboundDeltaResult uint8

const (
	// Invalid zero value.
	_ inboundDeltaResult = iota

	// Apply the delta to local state.
	inboundDeltaApply

	// This was redundant information,
	// so just drop the value.
	inboundDeltaDrop

	// Something was wrong with the value.
	// Rejecting the value should be considered as
	// the peer causing a protocol violation.
	inboundDeltaReject
)

func NewSession[
	PktIn any, PktOut wspacket.OutboundPacket,
	DeltaIn, DeltaOut any,
](
	log *slog.Logger,
	tracer dtrace.Tracer,
	protocolID byte,
	sessionID, appHeader []byte,
	state wspacket.CentralState[PktIn, PktOut, DeltaIn, DeltaOut],
	deltas *dpubsub.Stream[DeltaOut],
) *Session[PktIn, PktOut, DeltaIn, DeltaOut] {
	if len(appHeader) >= (1 << 16) {
		panic(fmt.Errorf(
			"BUG: app header size must fit in 16 bits (got length %d)",
			len(appHeader),
		))
	}

	// Assuming it's worth it to have a single contiguous copy
	// of the header that every outbound worker can use
	// in a single call to SendStream.Write.
	h := make([]byte, 1+len(sessionID)+2+len(appHeader))
	h[0] = protocolID
	_ = copy(h[1:], sessionID)

	binary.BigEndian.PutUint16(
		h[1+len(sessionID):],
		uint16(len(appHeader)),
	)

	_ = copy(h[1+len(sessionID)+2:], appHeader)

	return &Session[PktIn, PktOut, DeltaIn, DeltaOut]{
		log: log,

		tracer: tracer,

		header:    h,
		sessionID: h[1 : 1+len(sessionID)],

		state:  state,
		deltas: deltas,

		// Unbuffered since caller blocks anyway.
		acceptStreamRequests: make(chan acceptStreamRequest),
		inboundDeltaArrivals: make(chan inboundDeltaArrival[DeltaIn]),
	}
}

func (s *Session[PktIn, PktOut, DeltaIn, DeltaOut]) Run(
	ctx context.Context,
	parentWG *sync.WaitGroup,
	conns map[dcert.LeafCertHandle]dconn.Conn,
	connChanges *dpubsub.Stream[dconn.Change],
) {
	defer parentWG.Done()

	ctx, span := s.tracer.Start(
		ctx,
		"wingspan session main loop",
		dtrace.WithAttributes(
			dtrace.LazyHexAttr("wingspan.session.id", s.sessionID),
		),
	)
	defer span.End()

	var wg sync.WaitGroup
	defer wg.Wait()

	rs := s.initializeConns(ctx, &wg, conns)
	if rs == nil {
		// This can only happen with context cancellation.
		return
	}

	for {
		select {
		case <-ctx.Done():
			return

		case <-connChanges.Ready:
			cc := connChanges.Val
			connChanges = connChanges.Next
			lh := cc.Conn.Chain.LeafHandle
			if cc.Adding {
				conns[lh] = cc.Conn
				state, err := s.addRemoteState(ctx, &wg, cc.Conn)
				if err == nil {
					rs[lh] = state
				} else {
					if errors.Is(err, context.Canceled) {
						return
					}
					s.log.Info("TODO: handle failure to add remote state", "err", err)
				}
			} else {
				rs[lh].Cancel(nil) // TODO: use sentinel error here.

				delete(rs, lh)
				delete(conns, lh)
			}

		case req := <-s.acceptStreamRequests:
			// TODO: how should this handle a request
			// whose connection is not in the conns map?
			lh := req.Conn.Chain.LeafHandle

			r := rs[lh]
			if r.InboundStreamCh == nil {
				panic(errors.New("TODO: handle multiple streams from same peer"))
			}

			// No select since this channel is one-buffered.
			is, m, err := s.state.NewInboundRemoteState(ctx)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				panic(fmt.Errorf(
					"TODO: handle error from NewInboundRemoteState: %w", err,
				))
			}

			r.InboundStreamCh <- InboundStream[PktIn, DeltaIn, DeltaOut]{
				Stream: req.Stream,
				State:  is,
				Deltas: m,
			}
			span.AddEvent(
				"created inbound stream",
				dtrace.WithAttributes(
					dtrace.RemoteAddrAttr(req.Conn.QUIC),
				),
			)

			close(req.Resp)

			// Clear the InboundStreamCh so a second accept stream request will fail.
			r.InboundStreamCh = nil
			rs[lh] = r // Reassign due to map values not being references.

		case req := <-s.inboundDeltaArrivals:
			var res inboundDeltaResult
			err := s.state.UpdateFromPeer(ctx, req.Delta)
			switch {
			case err == nil:
				res = inboundDeltaApply
				span.AddEvent("Going to apply update from peer")
			case errors.Is(err, wspacket.ErrRedundantUpdate):
				res = inboundDeltaDrop
				span.AddEvent("Going to drop redundant update from peer")
			default:
				s.log.Info(
					"Failed to apply update from remote",
					"err", err,
				)
				res = inboundDeltaReject
				span.AddEvent(
					"Going to reject failed update from peer",
					dtrace.WithAttributes(
						dtrace.ErrorAttr(err),
					),
				)
			}

			// Response channel assumed to be buffered.
			req.Resp <- res
		}
	}
}

// remoteState is the centralized value used to track
// [Session] state for a single network peer.
type remoteState[
	PktIn any, PktOut wspacket.OutboundPacket,
	DeltaIn, DeltaOut any,
] struct {
	Conn dconn.Conn

	OW *OutboundWorker[PktIn, PktOut, DeltaIn, DeltaOut]
	IW *InboundWorker[PktIn, DeltaIn, DeltaOut]

	InboundStreamCh chan<- InboundStream[PktIn, DeltaIn, DeltaOut]

	Cancel context.CancelCauseFunc
}

// initializeConns sets up the workers for any pre-existing connections.
// Further new connections are handled in the session's main loop.
//
// If the context is canceled while setting up workers,
// initializeConns returns nil, as a signal to the caller.
func (s *Session[PktIn, PktOut, DeltaIn, DeltaOut]) initializeConns(
	ctx context.Context,
	wg *sync.WaitGroup,
	conns map[dcert.LeafCertHandle]dconn.Conn,
) map[dcert.LeafCertHandle]remoteState[PktIn, PktOut, DeltaIn, DeltaOut] {
	m := make(map[dcert.LeafCertHandle]remoteState[PktIn, PktOut, DeltaIn, DeltaOut], len(conns))

	for h, conn := range conns {
		rs, err := s.addRemoteState(ctx, wg, conn)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				// Shutting down.
				return nil
			}

			s.log.Info("TODO: handle error when adding remote state", "err", err)
			continue
		}
		m[h] = rs
	}

	return m
}

// addRemoteState starts goroutines for the inbound and outbound workers
// to be associated with the given connection.
func (s *Session[PktIn, PktOut, DeltaIn, DeltaOut]) addRemoteState(
	ctx context.Context,
	wg *sync.WaitGroup,
	conn dconn.Conn,
) (remoteState[PktIn, PktOut, DeltaIn, DeltaOut], error) {
	rs, m, err := s.state.NewOutboundRemoteState(ctx)
	if err != nil {
		zero := remoteState[PktIn, PktOut, DeltaIn, DeltaOut]{}
		return zero, fmt.Errorf("failed to make outbound remote state: %w", err)
	}

	log := s.log.With("remote", conn.QUIC.RemoteAddr().String())

	ow := NewOutboundWorker[PktIn, PktOut, DeltaIn, DeltaOut](
		log.With("worker", "outbound"),
		s.tracer,
		s.header,
		rs,
		m,
	)
	iw := NewInboundWorker[PktIn, DeltaIn, DeltaOut](
		log.With("worker", "inbound"),
		s.tracer,
		s.inboundDeltaArrivals,
	)

	peerReceivedCh := make(chan DeltaIn, 8) // Arbitrary size.

	ctx, cancel := context.WithCancelCause(ctx)

	wg.Add(2)
	const headerTimeout = 5 * time.Millisecond // TODO: make configurable
	go ow.Run(ctx, wg, conn.QUIC, headerTimeout, peerReceivedCh)

	inboundStreamCh := make(chan InboundStream[PktIn, DeltaIn, DeltaOut], 1)
	go iw.Run(ctx, wg, inboundStreamCh, peerReceivedCh)

	return remoteState[PktIn, PktOut, DeltaIn, DeltaOut]{
		Conn: conn,

		OW: ow,
		IW: iw,

		InboundStreamCh: inboundStreamCh,

		Cancel: cancel,
	}, nil
}

func (s *Session[PktIn, PktOut, DeltaIn, DeltaOut]) AcceptStream(
	ctx context.Context,
	conn dconn.Conn,
	rs dquic.ReceiveStream,
) error {
	req := acceptStreamRequest{
		Conn:   conn,
		Stream: rs,
		Resp:   make(chan struct{}),
	}

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case s.acceptStreamRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-req.Resp:
		return nil
	}
}
