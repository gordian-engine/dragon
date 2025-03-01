package dpdynamic

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

// Protocol handles a newly accepted stream that has not yet been identified.
type Protocol struct {
	Log *slog.Logger

	Cfg Config
}

type Config struct {
	IdentifyStreamTimeout time.Duration

	NowFn func() time.Time
}

func (c Config) Now() time.Time {
	if c.NowFn != nil {
		return c.NowFn()
	}

	return time.Now()
}

type Result struct {
	ShuffleMessage *dproto.ShuffleMessage

	ApplicationProtocolID uint8
}

func (p *Protocol) Run(ctx context.Context, s quic.Stream) (Result, error) {
	var h handler = identifyStreamHandler{
		OuterLog: p.Log,
		Cfg:      &p.Cfg,
	}
	var res Result

	for {
		next, err := h.Handle(ctx, s, &res)
		if err != nil {
			return res, fmt.Errorf(
				"failure handling dynamic stream; step = %s : %w",
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
