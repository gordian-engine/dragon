package dpadmission

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type forwardJoinHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h forwardJoinHandler) Handle(
	ctx context.Context, s quic.Stream, res *Result,
) (handler, error) {
	// Now that we know we are reading a forward join message,
	// we can set an appropriate deadline.
	if err := s.SetReadDeadline(h.Cfg.Now().Add(h.Cfg.AcceptForwardJoinTimeout)); err != nil {
		return nil, fmt.Errorf(
			"failed to set read deadline when accepting forward join: %w", err,
		)
	}

	var msg dproto.ForwardJoinMessage
	if err := msg.Decode(s); err != nil {
		return nil, fmt.Errorf(
			"failed to decode forward join message: %w", err,
		)
	}

	res.ForwardJoinMessage = &msg

	return nil, nil
}

func (h forwardJoinHandler) Name() string {
	return "Accept Forward Join"
}
