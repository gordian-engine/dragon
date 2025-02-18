package dbsjoin

import (
	"context"
	"fmt"
	"log/slog"

	"dragon.example/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type sendNeighborReplyHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h sendNeighborReplyHandler) Handle(
	ctx context.Context, c quic.Connection, res *Result,
) (streamHandler, error) {
	s := res.AdmissionStream

	// TODO: this needs to consult the kernel,
	// which means the Config needs a channel for the decision.
	//
	// TODO: the message could possibly move to this package.
	nReply := dproto.NeighborReplyMessage{Accepted: true}

	if err := s.SetWriteDeadline(
		h.Cfg.NowFn().Add(h.Cfg.OpenStreamTimeout),
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

	return streamAcceptHandler{
		OuterLog: h.OuterLog,
		Cfg:      h.Cfg,
	}, nil
}

func (h sendNeighborReplyHandler) Name() string {
	return "Send Neighbor Reply"
}
