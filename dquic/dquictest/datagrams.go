package dquictest

import (
	"context"

	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/dquic"
)

// SyncDatagramSender wraps a dquic.Conn
// and allows real calls to SendDatagram,
// but every call is blocked until a corresponding value
// arrives on the Continue channel.
type SyncDatagramSender struct {
	dquic.Conn

	Ctx      context.Context
	Continue <-chan struct{}
}

func (s SyncDatagramSender) SendDatagram(d []byte) error {
	select {
	case <-s.Ctx.Done():
		return context.Cause(s.Ctx)
	case <-s.Continue:
		// Go to the send.
	}

	return s.Conn.SendDatagram(d)
}

// DatagramDropper wraps a quic.Connection
// and turns SendDatagram into a no-op.
//
// This is useful for tests that need to simulate
// datagrams that do not reach the destination.
type DatagramDropper struct {
	dquic.Conn
}

func (d DatagramDropper) SendDatagram([]byte) error {
	return nil
}

// PubsubDatagramSender wraps a dquic.Conn
// that reroutes SendDatagram to put the byte values
// on a provided [*dpubsub.Stream].
// This allows unblocked behavior of SendDatagram
// but still allows test synchronization,
// without using particularly sized buffered channels.
type PubsubDatagramSender struct {
	dquic.Conn

	Stream *dpubsub.Stream[[]byte]
}

func (s *PubsubDatagramSender) SendDatagram(d []byte) error {
	s.Stream.Publish(d)
	s.Stream = s.Stream.Next

	return nil
}
