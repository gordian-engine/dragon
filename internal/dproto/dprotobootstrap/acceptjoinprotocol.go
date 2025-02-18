package dprotobootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"
)

type AcceptJoinProtocol struct {
	Log *slog.Logger

	Cfg AcceptJoinConfig

	Conn quic.Connection

	AdmissionStream quic.Stream
}

type AcceptJoinConfig struct {
	// Timeout for writing the neighbor request.
	NeighborRequestTimeout time.Duration

	// Timeout for receiving the neighbor reply.
	NeighborReplyTimeout time.Duration

	// Timeout to initialize both the disconnect and shuffle streams.
	InitializeStreamsTimeout time.Duration

	NowFn func() time.Time
}

func (c AcceptJoinConfig) Now() time.Time {
	if c.NowFn != nil {
		return c.NowFn()
	}

	return time.Now()
}

type AcceptJoinResult struct {
	DisconnectStream, ShuffleStream quic.Stream
}

func (p *AcceptJoinProtocol) Run(ctx context.Context) (AcceptJoinResult, error) {
	var h acceptJoinHandler = sendNeighborRequestHandler{
		OuterLog: p.Log,
		Cfg:      &p.Cfg,
	}

	var res AcceptJoinResult

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
	Handle(context.Context, quic.Connection, quic.Stream, *AcceptJoinResult) (acceptJoinHandler, error)
	Name() string
}
