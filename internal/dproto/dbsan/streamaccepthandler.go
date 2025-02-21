package dbsan

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dproto/dbscommon"
	"github.com/quic-go/quic-go"
)

type streamAcceptHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h streamAcceptHandler) Handle(
	ctx context.Context, c quic.Connection, _ quic.Stream, res *Result,
) (handler, error) {

	deadline := h.Cfg.Now().Add(h.Cfg.AcceptStreamsTimeout)

	acceptRes, err := dbscommon.AcceptStreams(ctx, c, deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to accept streams: %w", err)
	}

	res.Disconnect = acceptRes.Disconnect
	res.Shuffle = acceptRes.Shuffle

	return nil, nil
}

func (h streamAcceptHandler) Name() string {
	return "Accept Streams"
}
