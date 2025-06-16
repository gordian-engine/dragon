package wsi

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
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
	deltas *dchan.Multicast[D]
}

func NewSession[D any](
	log *slog.Logger,
	protocolID byte,
	sessionID, appHeader []byte,
	state wspacket.CentralState[D],
	deltas *dchan.Multicast[D],
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
	}
}

func (s *Session[D]) Run(
	ctx context.Context,
	parentWG *sync.WaitGroup,
	conns map[dcert.LeafCertHandle]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
) {
	defer parentWG.Done()

	var wg sync.WaitGroup
	defer wg.Wait()

	ot := s.initializeConns(ctx, &wg, conns)

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
				ot[lh] = s.addOutboundWorker(ctx, &wg, cc.Conn.QUIC)
			} else {
				t := ot[lh]
				t.Cancel(nil) // TODO: use sentinel error here.

				delete(ot, lh)
				delete(conns, lh)
			}
		}
	}
}

type outboundTracker[D any] struct {
	W *OutboundWorker[D]

	Cancel context.CancelCauseFunc
}

func (s *Session[D]) initializeConns(
	ctx context.Context,
	wg *sync.WaitGroup,
	conns map[dcert.LeafCertHandle]dconn.Conn,
) map[dcert.LeafCertHandle]outboundTracker[D] {
	outbound := make(map[dcert.LeafCertHandle]outboundTracker[D], len(conns))

	for h, conn := range conns {
		outbound[h] = s.addOutboundWorker(
			ctx, wg, conn.QUIC,
		)
	}

	return outbound
}

func (s *Session[D]) addOutboundWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	conn quic.Connection,
) outboundTracker[D] {
	rs, m, err := s.state.NewRemoteState(ctx)
	if err != nil {
		// TODO: probably should send back an error to the caller.
		panic(err)
	}

	ow := NewOutboundWorker(
		s.log.With("remote", conn.RemoteAddr().String()),
		s.header,
		rs,
		m,
	)

	ctx, cancel := context.WithCancelCause(ctx)
	t := outboundTracker[D]{
		W:      ow,
		Cancel: cancel,
	}

	wg.Add(1)
	const headerTimeout = 5 * time.Millisecond
	go ow.Run(ctx, wg, conn, headerTimeout)

	return t
}
