package dbsinbound

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/gordian-engine/dragon/internal/dprotoi"
	"github.com/quic-go/quic-go"
)

// Protocol is the protocol for accepting an incoming connection,
// before the first message has been sent on the bootstrap stream.
type Protocol struct {
	Log *slog.Logger

	Conn quic.Connection

	PeerCert *x509.Certificate

	Cfg Config
}

type Config struct {
	// Timeout for waiting for the incoming connection to open the stream.
	AcceptBootstrapStreamTimeout time.Duration

	// Timeout for the opened stream to send the new stream header.
	ReadStreamHeaderTimeout time.Duration

	// Grace periods for checking if remote join timestamp is acceptable.
	// Both durations should be positive, although zero is also accepted.
	GraceBeforeJoinTimestamp, GraceAfterJoinTimestamp time.Duration

	NowFn func() time.Time
}

func (c Config) Now() time.Time {
	if c.NowFn != nil {
		return c.NowFn()
	}

	return time.Now()
}

type Result struct {
	AdmissionStream quic.Stream

	JoinMessage *dprotoi.JoinMessage

	NeighborMessage *dprotoi.NeighborMessage
}

func (p *Protocol) Run(ctx context.Context) (Result, error) {
	var h incomingStreamHandler = acceptIncomingStreamHandler{
		OuterLog: p.Log,
		PeerCert: p.PeerCert,
		Cfg:      &p.Cfg,
	}

	var res Result

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
	Handle(context.Context, quic.Connection, *Result) (incomingStreamHandler, error)
	Name() string
}
