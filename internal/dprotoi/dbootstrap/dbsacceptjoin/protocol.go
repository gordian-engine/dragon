package dbsacceptjoin

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gordian-engine/dragon/dquic"
)

type Protocol struct {
	Log *slog.Logger

	Cfg Config

	Conn dquic.Conn

	AdmissionStream dquic.Stream
}

type Config struct {
	// Timeout for writing the neighbor request.
	NeighborRequestTimeout time.Duration

	// Timeout for receiving the neighbor reply.
	NeighborReplyTimeout time.Duration

	NowFn func() time.Time
}

func (c Config) Now() time.Time {
	if c.NowFn != nil {
		return c.NowFn()
	}

	return time.Now()
}

type Result struct {
	// TODO: maybe exclude the result then?
}

func (p *Protocol) Run(ctx context.Context) (Result, error) {
	var h acceptJoinHandler = sendNeighborRequestHandler{
		OuterLog: p.Log,
		Cfg:      &p.Cfg,
	}

	var res Result

	for {
		next, err := h.Handle(ctx, p.Conn, p.AdmissionStream, &res)
		if err != nil {
			// TODO: check context error
			return res, fmt.Errorf(
				"failure handling accept join protocol; step = %s : %w",
				h.Name(), err,
			)
		}

		if next == nil {
			return res, nil
		}

		h = next
	}
}

type acceptJoinHandler interface {
	Handle(context.Context, dquic.Conn, dquic.Stream, *Result) (acceptJoinHandler, error)
	Name() string
}
