package dragon_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

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

func TestNode_Dial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nw := dragontest.NewNetwork(t, ctx, dcatest.FastConfig(), dcatest.FastConfig())
	defer nw.Wait()
	defer cancel()

	conn, err := nw.Nodes[0].Node.DialPeer(ctx, nw.Nodes[1].UDP.LocalAddr())
	require.NoError(t, err)

	defer conn.Close(1, "test stopping")
}
