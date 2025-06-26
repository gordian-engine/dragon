package wsi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
	"github.com/quic-go/quic-go"
)

// Session is the internal representation of a session.
//
// Type parameter D is the delta type for state management.
type Session[D any] struct {
	log *slog.Logger

	// We store the full header only once on the session
	// and then reuse it for every outbound worker.
	header []byte

	state  wspacket.CentralState[D]
	deltas *dpubsub.Stream[D]

	acceptStreamRequests chan acceptStreamRequest
	inboundDeltaArrivals chan inboundDeltaArrival[D]
}

// acceptStreamRequest contains the details necessary
// to add an inbound stream to the [Session].
type acceptStreamRequest struct {
	Conn   dconn.Conn
	Stream quic.ReceiveStream
	Resp   chan struct{}
}

// inboundDeltaArrival is the value sent by an [InboundWorker]
// to the [Session], when the worker's peer sends a packet.
type inboundDeltaArrival[D any] struct {
	Delta D
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

func NewSession[D any](
	log *slog.Logger,
	protocolID byte,
	sessionID, appHeader []byte,
	state wspacket.CentralState[D],
	deltas *dpubsub.Stream[D],
) *Session[D] {
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

	return &Session[D]{
		log: log,

		header: h,

		state:  state,
		deltas: deltas,

		// Unbuffered since caller blocks anyway.
		acceptStreamRequests: make(chan acceptStreamRequest),
		inboundDeltaArrivals: make(chan inboundDeltaArrival[D]),
	}
}

func (s *Session[D]) Run(
	ctx context.Context,
	parentWG *sync.WaitGroup,
	parsePacketFn func(io.Reader) (D, error),
	conns map[dcert.LeafCertHandle]dconn.Conn,
	connChanges *dpubsub.Stream[dconn.Change],
) {
	defer parentWG.Done()

	var wg sync.WaitGroup
	defer wg.Wait()

	rs := s.initializeConns(ctx, &wg, conns, parsePacketFn)

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
				rs[lh] = s.addRemoteState(ctx, &wg, cc.Conn, parsePacketFn)
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

			r.InboundStreamCh <- InboundStream[D]{
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
type remoteState[D any] struct {
	Conn dconn.Conn

	OW *OutboundWorker[D]
	IW *InboundWorker[D]

	InboundStreamCh chan<- InboundStream[D]

	Cancel context.CancelCauseFunc
}

// initializeConns sets up the workers for any pre-existing connections.
// Further new connections are handled in the session's main loop.
func (s *Session[D]) initializeConns(
	ctx context.Context,
	wg *sync.WaitGroup,
	conns map[dcert.LeafCertHandle]dconn.Conn,
	parsePacketFn func(io.Reader) (D, error),
) map[dcert.LeafCertHandle]remoteState[D] {
	rs := make(map[dcert.LeafCertHandle]remoteState[D], len(conns))

	for h, conn := range conns {
		rs[h] = s.addRemoteState(ctx, wg, conn, parsePacketFn)
	}

	return rs
}

// addRemoteState starts goroutines for the inbound and outbound workers
// to be associated with the given connection.
func (s *Session[D]) addRemoteState(
	ctx context.Context,
	wg *sync.WaitGroup,
	conn dconn.Conn,
	parsePacketFn func(io.Reader) (D, error),
) remoteState[D] {
	rs, m, err := s.state.NewOutboundRemoteState(ctx)
	if err != nil {
		// TODO: probably should send back an error to the caller.
		panic(err)
	}

	log := s.log.With("remote", conn.QUIC.RemoteAddr().String())

	ow := NewOutboundWorker(
		log.With("worker", "outbound"),
		s.header,
		rs,
		m,
	)
	iw := NewInboundWorker(
		log.With("worker", "inbound"),
		s.inboundDeltaArrivals,
	)

	peerReceivedCh := make(chan D, 8) // Arbitrary size.

	ctx, cancel := context.WithCancelCause(ctx)

	wg.Add(2)
	const headerTimeout = 5 * time.Millisecond
	go ow.Run(ctx, wg, conn.QUIC, headerTimeout, peerReceivedCh)

	inboundStreamCh := make(chan InboundStream[D], 1)
	go iw.Run(ctx, wg, parsePacketFn, inboundStreamCh, peerReceivedCh)

	return remoteState[D]{
		Conn: conn,

		OW: ow,
		IW: iw,

		InboundStreamCh: inboundStreamCh,

		Cancel: cancel,
	}
}

func (s *Session[D]) AcceptStream(
	ctx context.Context,
	conn dconn.Conn,
	rs quic.ReceiveStream,
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
