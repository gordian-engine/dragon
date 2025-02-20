package dpadmission

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type acceptMessageHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h acceptMessageHandler) Handle(
	ctx context.Context, s quic.Stream, res *Result,
) (handler, error) {
	// Don't override the read deadline for the first message byte.
	var msgType [1]byte
	if _, err := io.ReadFull(s, msgType[:]); err != nil {
		return nil, fmt.Errorf("failed to read message type header: %w", err)
	}

	switch msgType[0] {
	case byte(dproto.ForwardJoinMessageType):
		return forwardJoinHandler{
			OuterLog: h.OuterLog,
			Cfg:      h.Cfg,
		}, nil
	default:
		return nil, fmt.Errorf("unknown admission message type %d", msgType[0])
	}
}

func (h acceptMessageHandler) Name() string {
	return "Admission Accept Message"
}
