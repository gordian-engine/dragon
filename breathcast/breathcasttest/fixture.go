package breathcasttest

import (
	"context"
	"testing"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/quic-go/quic-go"
)

// ProtocolFixture is a fixture for testing the breathcast protocol.
//
// Create an instance with [NewProtocolFixture].
type ProtocolFixture struct {
	ConnChanges []*dchan.Multicast[dconn.Change]
	Protocols   []*breathcast.Protocol2

	ListenerSet *dquictest.ListenerSet
}

// ProtocolFixtureConfig is the configuration for [NewProtocolFixture].
type ProtocolFixtureConfig struct {
	Nodes int

	ProtocolID byte

	BroadcastIDLength uint8
}

// NewProtocolFixture returns an initialized ProtocolFixture.
//
// The returned instance has no connections between any of the nodes.
// Use [*dquictest.ListenerSet.Dial] to create connections between nodes,
// and then send those connections on the corresponding ConnChanges
// so that the Protocol instances will respond to the new connection.
func NewProtocolFixture(
	t *testing.T, ctx context.Context, cfg ProtocolFixtureConfig,
) *ProtocolFixture {
	t.Helper()

	log := dtest.NewLogger(t)

	f := &ProtocolFixture{
		ConnChanges: make([]*dchan.Multicast[dconn.Change], cfg.Nodes),
		Protocols:   make([]*breathcast.Protocol2, cfg.Nodes),
		ListenerSet: dquictest.NewListenerSet(t, ctx, cfg.Nodes),
	}

	for i := range cfg.Nodes {
		cc := dchan.NewMulticast[dconn.Change]()
		p := breathcast.NewProtocol2(ctx, log.With("idx", i), breathcast.Protocol2Config{
			ConnectionChanges: cc,
			ProtocolID:        cfg.ProtocolID,
			BroadcastIDLength: cfg.BroadcastIDLength,
		})
		t.Cleanup(p.Wait)

		f.ConnChanges[i] = cc
		f.Protocols[i] = p
	}

	return f
}

// AddConnection adds the given connection.
// ownerIdx and peerIdx should correspond to the arguments given to
// [*dquictest.ListenerSet.Dial] (in order for the first returned connection,
// and swapped for the second returned connection).
func (f *ProtocolFixture) AddConnection(
	conn quic.Connection,
	ownerIdx, peerIdx int,
) {
	f.ConnChanges[ownerIdx].Set(dconn.Change{
		Conn: dconn.Conn{
			QUIC:  conn,
			Chain: f.ListenerSet.Leaves[peerIdx].Chain,
		},
		Adding: true,
	})
	f.ConnChanges[ownerIdx] = f.ConnChanges[ownerIdx].Next
}
