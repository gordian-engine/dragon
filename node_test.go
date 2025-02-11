package dragon_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"dragon.example/dragon"
	"dragon.example/dragon/dca/dcatest"
	"dragon.example/dragon/dragontest"
	"dragon.example/dragon/internal/dtest"
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
			},
		},
	}

	uc, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	require.NoError(t, err)
	defer uc.Close()

	log := dtest.NewLogger(t)
	n, err := dragon.NewNode(ctx, log, dragon.NodeConfig{
		UDPConn: uc,
		QUIC:    dragon.DefaultQUICConfig(),
		TLS:     &tc,
	})

	require.NoError(t, err)
	require.NotNil(t, n)

	defer n.Wait()
	defer cancel()
}

// Intra-network dial should just work.
func TestNode_Dial_ok(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nw := dragontest.NewNetwork(t, ctx, dcatest.FastConfig(), dcatest.FastConfig())
	defer nw.Wait()
	defer cancel()

	conn, err := nw.Nodes[0].Node.DialPeer(ctx, nw.Nodes[1].UDP.LocalAddr())
	require.NoError(t, err)

	defer conn.Close(1, "test stopping")
}

func TestNode_Dial_unrecognizedCert(t *testing.T) {
	t.Run("neither client nor server know each other", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		nw := dragontest.NewNetwork(t, ctx, dcatest.FastConfig(), dcatest.FastConfig())
		defer nw.Wait()
		defer cancel()

		out := dragontest.NewNetwork(t, ctx, dcatest.FastConfig())
		defer out.Wait()
		defer cancel()

		conn, err := out.Nodes[0].Node.DialPeer(ctx, nw.Nodes[0].UDP.LocalAddr())
		require.Error(t, err)
		require.Nil(t, conn)
	})

	t.Run("one-way knowledge", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfg1, cfg2 := dcatest.FastConfig(), dcatest.FastConfig()
		nw12 := dragontest.NewNetwork(t, ctx, cfg1, cfg2)
		defer nw12.Wait()
		defer cancel()

		nw123 := dragontest.NewNetwork(t, ctx, cfg1, cfg2, dcatest.FastConfig())
		defer nw123.Wait()
		defer cancel()

		t.Run("client knows server, but server does not know client", func(t *testing.T) {
			conn, err := nw123.Nodes[2].Node.DialPeer(ctx, nw12.Nodes[1].UDP.LocalAddr())
			require.Error(t, err)
			require.Nil(t, conn)
		})

		t.Run("server knows client, but client does not know server", func(t *testing.T) {
			conn, err := nw12.Nodes[1].Node.DialPeer(ctx, nw123.Nodes[2].UDP.LocalAddr())
			require.Error(t, err)
			require.Nil(t, conn)
		})
	})
}

func TestNode_Join(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nw := dragontest.NewNetwork(t, ctx, dcatest.FastConfig(), dcatest.FastConfig())
	defer nw.Wait()
	defer cancel()

	conn, err := nw.Nodes[0].Node.DialPeer(ctx, nw.Nodes[1].UDP.LocalAddr())
	require.NoError(t, err)

	defer func() {
		if err := conn.Close(1, "TODO"); err != nil {
			t.Logf("closing connection: %v", err)
		}
	}()

	require.NoError(t, conn.Join(ctx))

	// Short delay to allow background work to happen on the join request.
	time.Sleep(50 * time.Millisecond)

	// TODO: assert that each side has the peer in the active set.
}
