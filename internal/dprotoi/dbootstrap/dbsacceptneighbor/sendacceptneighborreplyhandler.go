package dbsacceptneighbor

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dprotoi"
	"github.com/quic-go/quic-go"
)

// sendAcceptNeighborReplyHandler sends an accepted neighbor message on the stream.
type sendAcceptNeighborReplyHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h sendAcceptNeighborReplyHandler) Handle(
	ctx context.Context, _ quic.Connection, s quic.Stream, res *Result,
) (handler, error) {
	if err := s.SetWriteDeadline(h.Cfg.Now().Add(h.Cfg.NeighborReplyTimeout)); err != nil {
		return nil, fmt.Errorf(
			"failed to set write deadline for outgoing neighbor reply: %w", err,
		)
	}

	out := [2]byte{byte(dprotoi.NeighborReplyMessageType), 1}
	if _, err := s.Write(out[:]); err != nil {
		return nil, fmt.Errorf("failed to send accepting neighbor reply: %w", err)
	}

	return nil, nil
}

func (h sendAcceptNeighborReplyHandler) Name() string {
	return "Send Neighbor Request"
}
