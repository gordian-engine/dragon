package dbssendjoin

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/gordian-engine/dragon/daddr"
	"github.com/quic-go/quic-go"
)

// Protocol is the outgoing bootstrap protocol initiated by a node joining the p2p network.
type Protocol struct {
	Log *slog.Logger

	// The underlying QUIC connection.
	// Other protocol implementations in other packages don't include this,
	// but this protocol bootstraps the other streams,
	// so we rely on the connection to create those streams.
	Conn quic.Connection

	Cfg Config
}

type Config struct {
	// The address to advertise on an outgoing join message.
	// This should already be configured at the node level.
	AdvertiseAddr string

	// Timeout for our open stream request to complete.
	OpenStreamTimeout time.Duration

	// How long to wait for the Neighbor reply to our join message.
	AwaitNeighborTimeout time.Duration

	// How long we will wait to accept streams from the new neighbor.
	AcceptStreamsTimeout time.Duration

	// Our TLS certificate.
	// This is used for signing the outgoing join message.
	// We sign the message because it gets forwarded to other peers
	// over the contact node's connection,
	// and we need to prove the origin of the message.
	Cert tls.Certificate

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

// Result is the result of bootstrapping:
// a collection of the three live protocol streams.
type Result struct {
	// This is the stream used for bootstrapping.
	// Following bootstrapping, it is used for the Forward Join message.
	AdmissionStream quic.Stream

	// We built and signed this message during the protocol,
	// and the kernel needs it for active set management.
	AA daddr.AddressAttestation
}

// Run runs the bootstrap outgoing join protocol to completion.
// If the error is nil,
// the returned Result has all its streams populated.
func (p *Protocol) Run(ctx context.Context) (Result, error) {
	var h streamHandler = sendJoinHandler{
		OuterLog: p.Log,
		Cfg:      &p.Cfg,
	}

	var res Result

	for {
		next, err := h.Handle(ctx, p.Conn, &res)
		if err != nil {
			// TODO: check context error.
			return res, fmt.Errorf(
				"failure handling bootstrap protocol; step = %s : %w",
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

type streamHandler interface {
	Handle(
		context.Context, quic.Connection, *Result,
	) (streamHandler, error)

	// User-facing name for logging and debugging.
	Name() string
}
