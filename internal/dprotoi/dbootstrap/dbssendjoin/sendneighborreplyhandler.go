package dbssendjoin

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dprotoi"
)

type sendNeighborReplyHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h sendNeighborReplyHandler) Handle(
	ctx context.Context, c dquic.Conn, res *Result,
) (streamHandler, error) {
	s := res.AdmissionStream

	// TODO: this needs to consult the kernel,
	// which means the Config needs a channel for the decision.
	//
	// TODO: the message could possibly move to this package.
	nReply := dprotoi.NeighborReplyMessage{Accepted: true}

	if err := s.SetWriteDeadline(
		h.Cfg.Now().Add(h.Cfg.OpenStreamTimeout),
	); err != nil {
		return nil, fmt.Errorf(
			"failed to set write deadline on stream: %w", err,
		)
	}

	if _, err := s.Write(nReply.Bytes()); err != nil {
		return nil, fmt.Errorf(
			"failed to send neighbor response: %w", err,
		)
	}

	return nil, nil
}

func (h sendNeighborReplyHandler) Name() string {
	return "Send Neighbor Reply"
}
