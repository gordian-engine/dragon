package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"testing"

	"github.com/gordian-engine/dragon"
	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/dragontest"
	"github.com/gordian-engine/dragon/dview/dviewrand"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestBroadcast(t *testing.T) {
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
	apps := make([]*IntegrationApp, nNodes)
	for i := range nNodes {
		var target net.Addr
		if i&1 == 1 {
			target = dNet.Nodes[0].UDP.LocalAddr()
		} else {
			target = dNet.Nodes[1].UDP.LocalAddr()
		}

		err := dNet.Nodes[i].Node.DialAndJoin(ctx, target)
		if i == 1 {
			// Node 1 will dial Node 0,
			// but Node 0 should have already dialed Node 1.
			// We almost always get the already-connected-to-certificate error,
			// but once in a while we get the address error.
			// Either one is acceptable in this case.
			require.Error(t, err)
			var certErr dragon.AlreadyConnectedToCertError
			var addrErr dragon.AlreadyConnectedToAddrError
			switch {
			case errors.As(err, &certErr):
				require.True(t, certErr.Chain.Leaf.Equal(dNet.Chains[0].Leaf))
			case errors.As(err, &addrErr):
				require.Equal(t, target.String(), addrErr.Addr)
			default:
				t.Fatalf("got unexpected error type %T (%v)", err, err)
			}
		} else {
			require.NoErrorf(
				t, err,
				"failed to dial from node %d", i,
			)
		}

		apps[i] = NewIntegrationApp(
			t, ctx,
			log.With("app_idx", i),
			dNet.ConnectionChanges[i],
		)
	}

	// The nodes are all dialed.
	// We need to set up an "application" for each node.
	for i := range nNodes {
		randData := dtest.RandomDataForTest(t, 16*1024+(10*i))

		broadcastID := fmt.Appendf(nil, "bc%02d", i)
		nonce := fmt.Appendf(nil, "nonce %d", i)

		po, err := breathcast.PrepareOrigination(randData, breathcast.PrepareOriginationConfig{
			MaxChunkSize: 1200,

			ProtocolID: breathcastProtocolID,

			BroadcastID: broadcastID,

			ParityRatio: 0.15,

			HeaderProofTier: 1,

			Hasher: bcsha256.Hasher{},

			HashSize: bcsha256.HashSize,

			Nonce: nonce,
		})
		require.NoError(t, err)

		jah, err := json.Marshal(BroadcastAppHeader{
			NData:   uint16(po.NumData),
			NParity: uint16(po.NumParity),

			TotalDataSize: len(randData),

			HashNonce: nonce,

			RootProofs: po.RootProof,

			ChunkSize: uint16(po.ChunkSize),
		})
		require.NoError(t, err)

		bop, err := apps[i].Breathcast.NewOrigination(ctx, breathcast.OriginationConfig{
			BroadcastID: broadcastID,

			AppHeader: jah,

			Packets: po.Packets,

			NData: uint16(po.NumData),

			TotalDataSize: len(randData),

			ChunkSize: po.ChunkSize,
		})
		require.NoError(t, err)

		// TODO: how to close out the broadcast operation?
		// It's associated with the entire protocol's context,
		// and it doesn't have a Stop or Cancel method (yet).
		_ = bop

		// We have no way to know the order that broadcasts will be observed,
		// so start a new goroutine for each app instance
		// and fan all of those in to one channel.
		ibFanIn := make(chan IncomingBroadcast, nNodes-1)
		for j := range nNodes {
			if j == i {
				continue
			}

			go func(a *IntegrationApp, j int) {
				select {
				case <-ctx.Done():
					return
				case ib := <-a.IncomingBroadcasts:
					ibFanIn <- ib
				}
			}(apps[j], j)
		}

		t.Skip("TODO: not all nodes always notify of broadcast yet")
		for range nNodes - 1 {
			_ = dtest.ReceiveSoon(t, ibFanIn)
		}

		break
	}
}
