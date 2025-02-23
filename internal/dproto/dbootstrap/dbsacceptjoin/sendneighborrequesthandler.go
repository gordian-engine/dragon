package dbsacceptjoin

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type sendNeighborRequestHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h sendNeighborRequestHandler) Handle(
	ctx context.Context, _ quic.Connection, s quic.Stream, res *Result,
) (acceptJoinHandler, error) {
	if err := s.SetWriteDeadline(h.Cfg.Now().Add(h.Cfg.NeighborRequestTimeout)); err != nil {
		return nil, fmt.Errorf(
			"failed to set write deadline for outgoing neighbor request: %w", err,
		)
	}

	t := [1]byte{byte(dproto.NeighborMessageType)}
	if _, err := s.Write(t[:]); err != nil {
		return nil, fmt.Errorf("failed to send neighbor request: %w", err)
	}

	return awaitNeighborReplyHandler{
		OuterLog: h.OuterLog,
		Cfg:      h.Cfg,
	}, nil
}

func (h sendNeighborRequestHandler) Name() string {
	return "Send Neighbor Request"
}
