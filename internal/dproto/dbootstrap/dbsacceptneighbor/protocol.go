package dbsacceptneighbor

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

	Cfg Config

	Conn quic.Connection

	Admission quic.Stream
}

type Config struct {
	// Timeout for sending the neighbor reply.
	NeighborReplyTimeout time.Duration

	// Timeout for accepting the remaining streams.
	AcceptStreamsTimeout time.Duration

	NowFn func() time.Time
}

func (c Config) Now() time.Time {
	if c.NowFn != nil {
		return c.NowFn()
	}

	return time.Now()
}

type Result struct {
	Disconnect, Shuffle quic.Stream
}

func (p *Protocol) RunAccept(ctx context.Context) (Result, error) {
	var h handler = sendAcceptNeighborReplyHandler{
		OuterLog: p.Log,
		Cfg:      &p.Cfg,
	}

	var res Result

	for {
		next, err := h.Handle(ctx, p.Conn, p.Admission, &res)
		if err != nil {
			// TODO: check context error
			return res, fmt.Errorf(
				"failure handling accept neighbor protocol; step = %s : %w",
				h.Name(), err,
			)
		}

		if next == nil {
			return res, nil
		}

		h = next
	}
}

func (p *Protocol) RunReject(ctx context.Context) error {
	// We only send two bytes for this entire flow,
	// so just inline it here for simplicity.
	if err := p.Admission.SetWriteDeadline(p.Cfg.Now().Add(p.Cfg.NeighborReplyTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline for rejecting neighbor reply: %w", err)
	}

	out := [2]byte{byte(dproto.NeighborReplyMessageType), 0}
	if _, err := p.Admission.Write(out[:]); err != nil {
		return fmt.Errorf("failed to send rejecting neighbor reply: %w", err)
	}

	return nil
}

type handler interface {
	Handle(context.Context, quic.Connection, quic.Stream, *Result) (handler, error)
	Name() string
}
