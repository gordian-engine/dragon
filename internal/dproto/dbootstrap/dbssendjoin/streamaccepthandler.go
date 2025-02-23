package dbssendjoin

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dproto/dbootstrap"
	"github.com/quic-go/quic-go"
)

type streamAcceptHandler struct {
	OuterLog *slog.Logger

	Cfg *Config
}

func (h streamAcceptHandler) Handle(
	ctx context.Context, c quic.Connection, res *Result,
) (streamHandler, error) {
	deadline := h.Cfg.NowFn().Add(h.Cfg.AcceptStreamsTimeout)

	acceptRes, err := dbootstrap.AcceptStreams(ctx, c, deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to accept streams: %w", err)
	}

	res.DisconnectStream = acceptRes.Disconnect
	res.ShuffleStream = acceptRes.Shuffle

	// We return a nil error and a nil handler here
	// because we have reached the terminal state of the admission stream setup.
	return nil, nil
}

func (h streamAcceptHandler) Name() string {
	return "Stream Accept"
}
