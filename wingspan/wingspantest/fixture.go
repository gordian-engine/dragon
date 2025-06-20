package wingspantest

import (
	"context"
	"testing"

	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/gordian-engine/dragon/wingspan"
	"github.com/quic-go/quic-go"
)

type ProtocolFixture struct {
	ConnChanges []*dchan.Multicast[dconn.Change]
	Protocols   []*wingspan.Protocol

	ListenerSet *dquictest.ListenerSet
}

// ProtocolFixtureConfig is the configuration for [NewProtocolFixture].
type ProtocolFixtureConfig struct {
	Nodes int

	ProtocolID byte

	SessionIDLength uint8
}

func NewProtocolFixture(
	t *testing.T, ctx context.Context, cfg ProtocolFixtureConfig,
) *ProtocolFixture {
	t.Helper()

	log := dtest.NewLogger(t)

	f := &ProtocolFixture{
		ConnChanges: make([]*dchan.Multicast[dconn.Change], cfg.Nodes),
		Protocols:   make([]*wingspan.Protocol, cfg.Nodes),
		ListenerSet: dquictest.NewListenerSet(t, ctx, cfg.Nodes),
	}

	for i := range cfg.Nodes {
		cc := dchan.NewMulticast[dconn.Change]()
		p := wingspan.NewProtocol(ctx, log.With("idx", i), wingspan.ProtocolConfig{
			ConnectionChanges: cc,
			ProtocolID:        cfg.ProtocolID,
			SessionIDLength:   cfg.SessionIDLength,
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
