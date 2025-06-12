package integration

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dragontest"
	"github.com/gordian-engine/dragon/dview/dviewrand"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestRandViewManager(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping due to short mode")
	}

	for _, c := range []struct {
		nNodes int

		active, passive int
	}{
		// This are just some arbitrary selections that seem to pass consistently.
		{nNodes: 5, active: 4, passive: 6},
		{nNodes: 8, active: 3, passive: 6},
		{nNodes: 10, active: 12, passive: 3},
	} {
		name := fmt.Sprintf(
			"nNodes=%d active=%d passive=%d",
			c.nNodes, c.active, c.passive,
		)
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testRandViewManager(
				t,
				c.nNodes,
				c.active, c.passive,
			)
		})
	}
}

func testRandViewManager(
	t *testing.T,
	nNodes, activeViewSize, passiveViewSize int,
) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := dtest.NewLogger(t)

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
					ActiveViewSize:  activeViewSize,
					PassiveViewSize: passiveViewSize,

					// Unique seed for each node.
					RNG: rand.New(rand.NewPCG(uint64(idx), uint64(activeViewSize*passiveViewSize))),
				},
			)
			return out
		},
	)

	// First build up all the node IDs,
	// because each connection observer needs this mapping.
	nodeIDsByLeafCert := make(map[dcert.LeafCertHandle]int, nNodes)
	connObservers := make([]*connObserver, nNodes)
	for i := range nNodes {
		nodeIDsByLeafCert[dNet.Chains[i].LeafHandle] = i
		connObservers[i] = newConnObserver(t, nodeIDsByLeafCert)
	}

	for i, o := range connObservers {
		go o.run(ctx, dNet.ConnectionChanges[i])
	}
	defer cancel()

	// Now dial everything.
	// Each node alternates connecting to node 0 or 1,
	// so they don't all dial the same peer,
	// but they dial a small set of nodes which should propagate correctly.
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
	}

	// Short sleep to give network time to stabilize if necessary.
	// It might be better to actually add another way
	// to see some elapsed time without any connection changes,
	// but for now this is good enough.
	time.Sleep(200 * time.Millisecond)

	// Now we track all the connected nodes using "union find":
	// https://en.wikipedia.org/wiki/Disjoint-set_data_structure
	groups := make([]*bitset.BitSet, nNodes)
	for i, o := range connObservers {
		bs := bitset.MustNew(uint(nNodes))
		bs.Set(uint(i))
		groups[i] = bs

		cn := o.ConnectedNodes()

		// Make the bitset for the current node.
		for _, ci := range cn {
			bs.Set(uint(ci))
		}

		// Now, this newest bitset takes precedence
		// over any previously created bitset.
		for _, ci := range cn {
			if groups[ci] == nil {
				// Connected to a node whose bitset we haven't created yet.
				break
			}
			bs.InPlaceUnion(groups[ci])
			groups[ci] = bs
		}

		// One last adjustment:
		// merge any other groups that we weren't directly connected to.
		for j := range i {
			if groups[j] == bs {
				// Already merged.
				continue
			}

			if groups[j].IntersectionCardinality(bs) > 0 {
				bs.InPlaceUnion(groups[j])
				groups[j] = bs
			}
		}
	}

	// Finally, if the graph is fully connected,
	// the last bitset should have all the bits set.
	finalGroup := groups[len(groups)-1]
	if finalGroup.Count() != uint(nNodes) {
		t.Error("FAIL: graph was not fully connected")

		seen := map[*bitset.BitSet]struct{}{}
		for _, g := range groups {
			if _, ok := seen[g]; ok {
				continue
			}
			seen[g] = struct{}{}

			t.Error(g.String())
		}
		t.FailNow()
	}
	require.Equalf(
		t, uint(nNodes), finalGroup.Count(),
		"final bitset was incomplete: %s", finalGroup.String(),
	)
}

// connObserver is a helper for TestRandViewManager
// that allows interrogating the node IDs
// connected to a particular node.
type connObserver struct {
	Done chan struct{}

	nodeIDsByLeafCert map[dcert.LeafCertHandle]int

	nodeRequests chan chan []int
}

func newConnObserver(
	t *testing.T,
	nodeIDsByLeafCert map[dcert.LeafCertHandle]int,
) *connObserver {
	o := &connObserver{
		Done: make(chan struct{}),

		nodeIDsByLeafCert: nodeIDsByLeafCert,

		nodeRequests: make(chan chan []int),
	}
	t.Cleanup(func() {
		<-o.Done
	})
	return o
}

func (o *connObserver) run(ctx context.Context, connChanges <-chan dconn.Change) {
	defer close(o.Done)

	connectedNodeIDs := map[int]struct{}{}

	for {
		select {
		case <-ctx.Done():
			return

		case cc := <-connChanges:
			nodeID := o.nodeIDsByLeafCert[cc.Conn.Chain.LeafHandle]
			if cc.Adding {
				connectedNodeIDs[nodeID] = struct{}{}
			} else {
				delete(connectedNodeIDs, nodeID)
			}

		case ch := <-o.nodeRequests:
			out := make([]int, 0, len(connectedNodeIDs))
			for i := range connectedNodeIDs {
				out = append(out, i)
			}

			ch <- out
		}
	}
}

// ConnectedNodes returns a sorted slice of the node indices
// that the observer's node is connected to.
func (o *connObserver) ConnectedNodes() []int {
	nodesCh := make(chan []int, 1)

	// Not bothering with context checking in this particular test.
	o.nodeRequests <- nodesCh

	got := <-nodesCh
	sort.Ints(got)
	return got
}
