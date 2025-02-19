package dbsjoin

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

// awaitNeighborRequestHandler is a handler for a joining node.
// After sending the initial Join message,
// the joining node expects a Neighbor request from the contact node
// over that same stream.
// If that doesn't happen, we anticipate the neighbor to disconnect.
type awaitNeighborRequestHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h awaitNeighborRequestHandler) Handle(
	ctx context.Context, c quic.Connection, res *Result,
) (streamHandler, error) {
	s := res.AdmissionStream
	if err := s.SetReadDeadline(h.Cfg.NowFn().Add(h.Cfg.AwaitNeighborTimeout)); err != nil {
		return nil, fmt.Errorf(
			"failed to set read deadline on stream: %w", err,
		)
	}

	// The neighbor request is just the single byte.
	var nReq [1]byte
	if _, err := io.ReadFull(s, nReq[:]); err != nil {
		return nil, fmt.Errorf("failed to read neighbor reply: %w", err)
	}
	if nReq[0] != byte(dproto.NeighborMessageType) {
		return nil, fmt.Errorf("expected neighbor message but got %d", nReq)
	}

	// We have the request, so next we send the reply.
	return sendNeighborReplyHandler{
		OuterLog: h.OuterLog,
		Cfg:      h.Cfg,
	}, nil
}

func (h awaitNeighborRequestHandler) Name() string {
	return "Await Neighbor Request"
}
