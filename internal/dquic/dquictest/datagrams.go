package dquictest

import (
	"context"

	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/quic-go/quic-go"
)

// SyncDatagramSender wraps a quic.Connection
// and allows real calls to SendDatagram,
// but every call is blocked until a corresponding value
// arrives on the Continue channel.
type SyncDatagramSender struct {
	quic.Connection

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

	return s.Connection.SendDatagram(d)
}

// DatagramDropper wraps a quic.Connection
// and turns SendDatagram into a no-op.
//
// This is useful for tests that need to simulate
// datagrams that do not reach the destination.
type DatagramDropper struct {
	quic.Connection
}

func (d DatagramDropper) SendDatagram([]byte) error {
	return nil
}

// MulticastingDatagramSender wraps a quic.Connection
// that reroutes SendDatagram to put the byte values
// on a provided [*dchan.Multicast].
// This allows unblocked behavior of SendDatagram
// but still allows test syncrhonization,
// without using particularly sized buffered channels.
type MulticastingDatagramSender struct {
	quic.Connection

	Multicast *dchan.Multicast[[]byte]
}

func (s *MulticastingDatagramSender) SendDatagram(d []byte) error {
	s.Multicast.Set(d)
	s.Multicast = s.Multicast.Next

	return nil
}
