package dragon_test

import (
	"context"
	"crypto/tls"
	"math/rand/v2"
	"net"
	"testing"
	"time"

	"github.com/gordian-engine/dragon"
	"github.com/gordian-engine/dragon/dca/dcatest"
	"github.com/gordian-engine/dragon/dragontest"
	"github.com/gordian-engine/dragon/dview/dviewrand"
	"github.com/gordian-engine/dragon/dview/dviewtest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestNewNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca, err := dcatest.GenerateCA(dcatest.FastConfig())
	require.NoError(t, err)

	leaf, err := ca.CreateLeafCert(dcatest.LeafConfig{
		DNSNames: []string{"localhost"},
	})
	require.NoError(t, err)

	tc := tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{leaf.Cert.Raw},
				PrivateKey:  leaf.PrivKey,
				Leaf:        leaf.Cert,
			},
		},

		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	uc, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	require.NoError(t, err)
	defer uc.Close()

	log := dtest.NewLogger(t)
	n, err := dragon.NewNode(ctx, log, dragon.NodeConfig{
		UDPConn:     uc,
		QUIC:        dragon.DefaultQUICConfig(),
		TLS:         &tc,
		ViewManager: dviewtest.DenyingManager{},

		AdvertiseAddr: uc.LocalAddr().String(),
	})

	require.NoError(t, err)
	require.NotNil(t, n)

	defer n.Wait()
	defer cancel()
}

func TestNode_DialAndJoin_unrecognizedCert(t *testing.T) {
	t.Run("neither client nor server know each other", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		nw := dragontest.NewDefaultNetwork(t, ctx, dcatest.FastConfig(), dcatest.FastConfig())
		defer nw.Wait()
		defer cancel()

		out := dragontest.NewDefaultNetwork(t, ctx, dcatest.FastConfig())
		defer out.Wait()
		defer cancel()

		require.Error(t, out.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[0].UDP.LocalAddr()))
	})

	t.Run("one-way knowledge", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfg1, cfg2 := dcatest.FastConfig(), dcatest.FastConfig()
		nw12 := dragontest.NewDefaultNetwork(t, ctx, cfg1, cfg2)
		defer nw12.Wait()
		defer cancel()

		nw123 := dragontest.NewDefaultNetwork(t, ctx, cfg1, cfg2, dcatest.FastConfig())
		defer nw123.Wait()
		defer cancel()

		t.Run("client knows server, but server does not know client", func(t *testing.T) {
			require.Error(t, nw123.Nodes[2].Node.DialAndJoin(ctx, nw12.Nodes[1].UDP.LocalAddr()))
		})

		t.Run("server knows client, but client does not know server", func(t *testing.T) {
			require.Error(t, nw12.Nodes[1].Node.DialAndJoin(ctx, nw123.Nodes[2].UDP.LocalAddr()))
		})
	})
}

func TestNode_DialAndJoin_deny(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nw := dragontest.NewNetwork(
		t, ctx,
		[]dcatest.CAConfig{dcatest.FastConfig(), dcatest.FastConfig()},
		func(_ int, c dragontest.NodeConfig) dragon.NodeConfig {
			out := c.ToDragonNodeConfig()

			// Explicitly deny any join requests.
			out.ViewManager = dviewtest.DenyingManager{}

			return out
		},
	)
	defer nw.Wait()
	defer cancel()

	// No active views before join.
	require.Zero(t, nw.Nodes[0].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[1].Node.ActiveViewSize())

	// TLS should work but the request should be denied.
	// TODO: it would be better to do a more specific error assertion here.
	require.Error(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// And no active views were added.
	require.Zero(t, nw.Nodes[0].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[1].Node.ActiveViewSize())
}

func TestNode_DialAndJoin_accept(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nw := dragontest.NewNetwork(
		t, ctx,
		[]dcatest.CAConfig{dcatest.FastConfig(), dcatest.FastConfig()},
		func(_ int, c dragontest.NodeConfig) dragon.NodeConfig {
			out := c.ToDragonNodeConfig()

			// Explicitly accept join requests.
			out.ViewManager = dviewrand.New(
				dtest.NewLogger(t).With("node_sys", "view_manager"),
				dviewrand.Config{
					ActiveViewSize:  4,
					PassiveViewSize: 8,

					RNG: rand.New(rand.NewPCG(10, 20)), // Arbitrary fixed seed for this test.
				},
			)

			return out
		},
	)
	defer nw.Wait()
	defer cancel()

	// No active views before joining.
	require.Zero(t, nw.Nodes[0].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[1].Node.ActiveViewSize())

	require.NoError(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// Short delay to allow background work to happen on the join request.
	time.Sleep(50 * time.Millisecond)

	// Now both nodes report 1 active view member.
	require.Equal(t, 1, nw.Nodes[0].Node.ActiveViewSize())
	require.Equal(t, 1, nw.Nodes[1].Node.ActiveViewSize())
}

func TestNode_forwardJoin(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nw := dragontest.NewNetwork(
		t, ctx,
		[]dcatest.CAConfig{dcatest.FastConfig(), dcatest.FastConfig(), dcatest.FastConfig()},
		func(_ int, c dragontest.NodeConfig) dragon.NodeConfig {
			out := c.ToDragonNodeConfig()

			// Explicitly accept join requests.
			out.ViewManager = dviewrand.New(
				dtest.NewLogger(t).With("node_sys", "view_manager"),
				dviewrand.Config{
					ActiveViewSize:  4,
					PassiveViewSize: 8,

					RNG: rand.New(rand.NewPCG(10, 20)), // Arbitrary fixed seed for this test.
				},
			)

			return out
		},
	)
	defer nw.Wait()
	defer cancel()

	// No active views before joining.
	require.Zero(t, nw.Nodes[0].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[1].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[2].Node.ActiveViewSize())

	// Node 0 joins Node 1 first.
	require.NoError(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// Short delay to allow background work to happen on the join request.
	time.Sleep(50 * time.Millisecond)

	// Now both nodes report 1 active view member.
	require.Equal(t, 1, nw.Nodes[0].Node.ActiveViewSize())
	require.Equal(t, 1, nw.Nodes[1].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[2].Node.ActiveViewSize())

	// Now, Node 2 also joins Node 1.
	// This causes Node 1 to send a forward join to Node 0.
	require.NoError(t, nw.Nodes[2].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// Another short delay for background work.
	time.Sleep(50 * time.Millisecond)

	t.Skip("TODO: we are sending and receiving forward joins, but we need to handle them too")
	require.Equal(t, 2, nw.Nodes[0].Node.ActiveViewSize())
	require.Equal(t, 2, nw.Nodes[1].Node.ActiveViewSize())
	require.Equal(t, 2, nw.Nodes[2].Node.ActiveViewSize())
}
