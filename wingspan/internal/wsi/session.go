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
	"github.com/gordian-engine/dragon/wingspan/wspacket"
)

// Session is the internal representation of a session.
type Session[
	PktIn any, PktOut wspacket.OutboundPacket,
	DeltaIn, DeltaOut any,
] struct {
	log *slog.Logger

	// We store the full header only once on the session
	// and then reuse it for every outbound worker.
	header []byte

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

		header: h,

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

	var wg sync.WaitGroup
	defer wg.Wait()

	rs := s.initializeConns(ctx, &wg, conns)

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
				rs[lh] = s.addRemoteState(ctx, &wg, cc.Conn)
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
				panic(fmt.Errorf(
					"TODO: handle error from NewInboundRemoteState: %w", err,
				))
			}

			r.InboundStreamCh <- InboundStream[PktIn, DeltaIn, DeltaOut]{
				Stream: req.Stream,
				State:  is,
				Deltas: m,
			}

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
			case errors.Is(err, wspacket.ErrRedundantUpdate):
				res = inboundDeltaDrop
			default:
				s.log.Info(
					"Failed to apply update from remote",
					"err", err,
				)
				res = inboundDeltaReject
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
func (s *Session[PktIn, PktOut, DeltaIn, DeltaOut]) initializeConns(
	ctx context.Context,
	wg *sync.WaitGroup,
	conns map[dcert.LeafCertHandle]dconn.Conn,
) map[dcert.LeafCertHandle]remoteState[PktIn, PktOut, DeltaIn, DeltaOut] {
	rs := make(map[dcert.LeafCertHandle]remoteState[PktIn, PktOut, DeltaIn, DeltaOut], len(conns))

	for h, conn := range conns {
		rs[h] = s.addRemoteState(ctx, wg, conn)
	}

	return rs
}

// addRemoteState starts goroutines for the inbound and outbound workers
// to be associated with the given connection.
func (s *Session[PktIn, PktOut, DeltaIn, DeltaOut]) addRemoteState(
	ctx context.Context,
	wg *sync.WaitGroup,
	conn dconn.Conn,
) remoteState[PktIn, PktOut, DeltaIn, DeltaOut] {
	rs, m, err := s.state.NewOutboundRemoteState(ctx)
	if err != nil {
		// TODO: probably should send back an error to the caller.
		panic(err)
	}

	log := s.log.With("remote", conn.QUIC.RemoteAddr().String())

	ow := NewOutboundWorker[PktIn, PktOut, DeltaIn, DeltaOut](
		log.With("worker", "outbound"),
		s.header,
		rs,
		m,
	)
	iw := NewInboundWorker[PktIn, DeltaIn, DeltaOut](
		log.With("worker", "inbound"),
		s.inboundDeltaArrivals,
	)

	peerReceivedCh := make(chan DeltaIn, 8) // Arbitrary size.

	ctx, cancel := context.WithCancelCause(ctx)

	wg.Add(2)
	const headerTimeout = 5 * time.Millisecond
	go ow.Run(ctx, wg, conn.QUIC, headerTimeout, peerReceivedCh)

	inboundStreamCh := make(chan InboundStream[PktIn, DeltaIn, DeltaOut], 1)
	go iw.Run(ctx, wg, inboundStreamCh, peerReceivedCh)

	return remoteState[PktIn, PktOut, DeltaIn, DeltaOut]{
		Conn: conn,

		OW: ow,
		IW: iw,

		InboundStreamCh: inboundStreamCh,

		Cancel: cancel,
	}
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
