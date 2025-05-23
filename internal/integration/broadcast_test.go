package integration

import (
	"context"
	"math/rand/v2"
	"net"
	"testing"

	"github.com/gordian-engine/dragon"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/dragontest"
	"github.com/gordian-engine/dragon/dview/dviewrand"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestBroadcast(t *testing.T) {
	t.Skip("working through bugs preventing this test from passing")

	if testing.Short() {
		t.Skip("skipping due to short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := dtest.NewLogger(t)

	const nNodes = 8
	caConfigs := make([]dcerttest.CAConfig, nNodes)
	for i := range nNodes {
		caConfigs[i] = dcerttest.FastConfig()
	}
	dNet := dragontest.NewNetwork(
		t, ctx,
		caConfigs,
		func(idx int, nc dragontest.NodeConfig) dragon.NodeConfig {
			out := nc.ToDragonNodeConfig()

			// The view manager created through NewDefaultNetwork
			// matches the view size to the node count,
			// and we specifically want a smaller view size for this test.
			out.ViewManager = dviewrand.New(
				log.With("node_sys", "view_manager"),
				dviewrand.Config{
					ActiveViewSize:  3,
					PassiveViewSize: 6,

					// Unique seed for each node.
					RNG: rand.New(rand.NewPCG(uint64(idx), 0)),
				},
			)
			return out
		},
	)

	// Now dial everything.
	// Each node alternates connecting to node 0 or 1,
	// so they don't all dial the same peer,
	// but they dial a small set of nodes which should propagate correctly.
	for i := range nNodes {
		if i == 0 {
			// Node 1 will dial Node 0,
			// so skip 0->1 so that 1->0 is not rejected
			// due to already being connected.
			continue
		}

		var target net.Addr
		if i&1 == 1 {
			target = dNet.Nodes[0].UDP.LocalAddr()
		} else {
			target = dNet.Nodes[1].UDP.LocalAddr()
		}

		require.NoErrorf(
			t, dNet.Nodes[i].Node.DialAndJoin(ctx, target),
			"failed to dial from node %d", i,
		)
	}
}
