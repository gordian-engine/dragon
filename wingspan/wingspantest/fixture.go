package wingspantest

import (
	"context"
	"testing"

	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/gordian-engine/dragon/wingspan"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
	"github.com/quic-go/quic-go"
)

type ProtocolFixture[
	PktIn any, PktOut wspacket.OutboundPacket,
	DeltaIn, DeltaOut any,
] struct {
	ConnChanges []*dpubsub.Stream[dconn.Change]
	Protocols   []*wingspan.Protocol[PktIn, PktOut, DeltaIn, DeltaOut]

	ListenerSet *dquictest.ListenerSet
}

// ProtocolFixtureConfig is the configuration for [NewProtocolFixture].
type ProtocolFixtureConfig struct {
	Nodes int

	ProtocolID byte

	SessionIDLength uint8
}

func NewProtocolFixture[
	PktIn any, PktOut wspacket.OutboundPacket,
	DeltaIn, DeltaOut any,
](
	t *testing.T, ctx context.Context, cfg ProtocolFixtureConfig,
) *ProtocolFixture[PktIn, PktOut, DeltaIn, DeltaOut] {
	t.Helper()

	log := dtest.NewLogger(t)

	f := &ProtocolFixture[PktIn, PktOut, DeltaIn, DeltaOut]{
		ConnChanges: make([]*dpubsub.Stream[dconn.Change], cfg.Nodes),
		Protocols:   make([]*wingspan.Protocol[PktIn, PktOut, DeltaIn, DeltaOut], cfg.Nodes),
		ListenerSet: dquictest.NewListenerSet(t, ctx, cfg.Nodes),
	}

	for i := range cfg.Nodes {
		cc := dpubsub.NewStream[dconn.Change]()
		p := wingspan.NewProtocol[PktIn, PktOut, DeltaIn, DeltaOut](
			ctx, log.With("idx", i), wingspan.ProtocolConfig{
				ConnectionChanges: cc,
				ProtocolID:        cfg.ProtocolID,
				SessionIDLength:   cfg.SessionIDLength,
			},
		)
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
func (f *ProtocolFixture[PktIn, PktOut, DeltaIn, DeltaOut]) AddConnection(
	conn quic.Connection,
	ownerIdx, peerIdx int,
) {
	f.ConnChanges[ownerIdx].Publish(dconn.Change{
		Conn: dconn.Conn{
			QUIC:  conn,
			Chain: f.ListenerSet.Leaves[peerIdx].Chain,
		},
		Adding: true,
	})
	f.ConnChanges[ownerIdx] = f.ConnChanges[ownerIdx].Next
}
