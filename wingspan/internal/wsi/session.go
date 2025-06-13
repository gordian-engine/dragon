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
	"github.com/quic-go/quic-go"
)

// Session is the internal representation of a session.
type Session struct {
	log *slog.Logger

	// We store the full header only once on the sessoin
	// and then reuse it for every outbound worker.
	header []byte
}

func NewSession(
	log *slog.Logger,
	protocolID byte,
	sessionID, appHeader []byte,
) *Session {
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

	return &Session{
		log: log,

		header: h,
	}
}

func (s *Session) Run(
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

type outboundTracker struct {
	W *OutboundWorker

	Cancel context.CancelCauseFunc
}

func (s *Session) initializeConns(
	ctx context.Context,
	wg *sync.WaitGroup,
	conns map[dcert.LeafCertHandle]dconn.Conn,
) map[dcert.LeafCertHandle]outboundTracker {
	outbound := make(map[dcert.LeafCertHandle]outboundTracker, len(conns))

	for h, conn := range conns {
		outbound[h] = s.addOutboundWorker(
			ctx, wg, conn.QUIC,
		)
	}

	return outbound
}

func (s *Session) addOutboundWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	conn quic.Connection,
) outboundTracker {
	ow := NewOutboundWorker(
		s.log.With(), // TODO
		s.header,
	)

	ctx, cancel := context.WithCancelCause(ctx)
	t := outboundTracker{
		W:      ow,
		Cancel: cancel,
	}

	wg.Add(1)
	const headerTimeout = 5 * time.Millisecond
	go ow.Run(ctx, wg, conn, headerTimeout)

	return t
}
