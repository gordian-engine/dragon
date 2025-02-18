package dprotobootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"
)

type IncomingProtocol struct {
	Log *slog.Logger

	Conn quic.Connection

	Cfg IncomingConfig
}

type IncomingConfig struct {
	// Timeout for waiting for the incoming connection to open the stream.
	AcceptBootstrapStreamTimeout time.Duration

	// Timeout for the opened stream to send the new stream header.
	ReadStreamHeaderTimeout time.Duration

	// Grace periods for checking if remote join timestamp is acceptable.
	// Both durations should be positive, although zero is also accepted.
	GraceBeforeJoinTimestamp, GraceAfterJoinTimestamp time.Duration

	NowFn func() time.Time
}

func (c IncomingConfig) Now() time.Time {
	if c.NowFn != nil {
		return c.NowFn()
	}

	return time.Now()
}

type IncomingResult struct {
	AdmissionStream quic.Stream

	JoinAddr string

	// TODO: this will eventually hold a neighbor request too.
}

func (p *IncomingProtocol) Run(ctx context.Context) (IncomingResult, error) {
	var h incomingStreamHandler = acceptIncomingStreamHandler{
		OuterLog: p.Log,
		Cfg:      &p.Cfg,
	}

	var res IncomingResult

	for {
		next, err := h.Handle(ctx, p.Conn, &res)
		if err != nil {
			// TODO: check context error
			return res, fmt.Errorf(
				"failure handling incoming bootstrap protocol; step = %s : %w",
				h.Name(), err,
			)
		}

		if next == nil {
			// Join ran to completion.
			return res, nil
		}

		h = next
	}
}

type incomingStreamHandler interface {
	Handle(context.Context, quic.Connection, *IncomingResult) (incomingStreamHandler, error)
	Name() string
}
