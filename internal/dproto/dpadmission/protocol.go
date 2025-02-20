package dpadmission

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type Protocol struct {
	Log *slog.Logger

	Stream quic.Stream

	Cfg Config
}

type Config struct {
	AcceptForwardJoinTimeout time.Duration

	// How the admission determines current time.
	// Defaults to [time.Now] if nil.
	NowFn func() time.Time
}

func (c Config) Now() time.Time {
	if c.NowFn != nil {
		return c.NowFn()
	}

	return time.Now()
}

type Result struct {
	ForwardJoinMessage *dproto.ForwardJoinMessage
}

func (p *Protocol) Run(ctx context.Context) (Result, error) {
	var h handler = acceptMessageHandler{
		OuterLog: p.Log,
		Cfg:      &p.Cfg,
	}
	var res Result

	for {
		next, err := h.Handle(ctx, p.Stream, &res)
		if err != nil {
			// TODO: check context error.
			return res, fmt.Errorf(
				"failure handling incoming admission protocol; step = %s : %w",
				h.Name(), err,
			)
		}

		if next == nil {
			return res, nil
		}

		h = next
	}
}

type handler interface {
	Handle(
		context.Context, quic.Stream, *Result,
	) (handler, error)

	// User-facing name for logging and debugging.
	Name() string
}
