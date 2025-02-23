package dbssendneighbor

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"
)

// Protocol is the outgoing bootstrap protocol initiated by
// a "member node" sending a neighbor request to a "candidate peer".
type Protocol struct {
	Log *slog.Logger

	Conn quic.Connection

	Cfg Config
}

type Config struct {
	// The address to advertise on the outgoing neighbor message.
	// This is needed so the node we join can include us in outbound shuffles.
	AdvertiseAddr string

	// Our TLS certificate.
	// This is used for signing the outgoing address attestation
	// for the neighbor request.
	Cert tls.Certificate

	// Timeout for our open stream request to complete.
	OpenStreamTimeout time.Duration

	// How long to wait for the neighbor reply message
	// after we open the stream.
	AwaitNeighborReplyTimeout time.Duration

	// How long to allow for initializing the streams.
	InitializeStreamsTimeout time.Duration

	NowFn func() time.Time
}

func (c Config) Now() time.Time {
	if c.NowFn != nil {
		return c.NowFn()
	}

	return time.Now()
}

type Result struct {
	Admission  quic.Stream
	Disconnect quic.Stream
	Shuffle    quic.Stream
}

func (p *Protocol) Run(ctx context.Context) (Result, error) {
	var h handler = sendNeighborHandler{
		OuterLog: p.Log,
		Cfg:      &p.Cfg,
	}

	var res Result

	for {
		next, err := h.Handle(ctx, p.Conn, &res)
		if err != nil {
			// TODO: check context error.
			return res, fmt.Errorf(
				"failure handling neighbor bootstrap protocol; step = %s : %w",
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
		context.Context, quic.Connection, *Result,
	) (handler, error)

	Name() string
}
