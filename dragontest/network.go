package dragontest

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"testing"

	"dragon.example/dragon"
	"dragon.example/dragon/dca/dcatest"
	"dragon.example/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

// Network contains a collection of NetworkNode values,
// to simplify tests that require multiple nodes.
type Network struct {
	Log *slog.Logger

	Pool *dcatest.TrustPool

	Nodes []NetworkNode
}

// NetworkNode contains the details for a node in this test network.
type NetworkNode struct {
	Node *dragon.Node

	UDP *net.UDPConn
}

// NewNetwork accepts a testing.T and a set of CA configurations,
// then returns a Network.
//
// If any error occurs while creating the network,
// t.Fatal is called.
//
// t.Cleanup is used extensively to ensure resources are claned up.
func NewNetwork(t *testing.T, ctx context.Context, cfgs ...dcatest.CAConfig) *Network {
	t.Helper()

	log := dtest.NewLogger(t)

	tp, err := dcatest.NewTrustPool(cfgs...)
	require.NoError(t, err)

	nodes := make([]NetworkNode, len(cfgs))
	for i, ca := range tp.CAs {
		// Create listener first.
		uc, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 0,
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			if err := uc.Close(); err != nil {
				t.Logf("Error closing UDP listener: %v", err)
			}
		})

		// Now we need the leaf certificate for the node.
		l, err := ca.CreateLeafCert(dcatest.LeafConfig{
			DNSNames: []string{"localhost"},
		})
		require.NoError(t, err)

		tc := tls.Config{
			// The certificate this client presents.
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{l.Cert.Raw},
					PrivateKey:  l.PrivKey,
				},
			},

			RootCAs: tp.Pool,
		}

		n, err := dragon.NewNode(ctx, log.With("node", i), dragon.NodeConfig{
			UDPConn: uc,
			QUIC:    dragon.DefaultQUICConfig(),
			TLS:     &tc,
		})
		require.NoError(t, err)

		// This cleanup call necessitates that the context is cancelled before the end of the test.
		t.Cleanup(n.Wait)

		nodes[i] = NetworkNode{
			Node: n,
			UDP:  uc,
		}
	}

	return &Network{
		Log:   log,
		Pool:  tp,
		Nodes: nodes,
	}
}

func (n *Network) Wait() {
	for _, node := range n.Nodes {
		node.Node.Wait()
	}
}
