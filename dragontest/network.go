package dragontest

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"testing"

	"dragon.example/dragon"
	"dragon.example/dragon/dca/dcatest"
	"dragon.example/dragon/deval/devaltest"
	"dragon.example/dragon/internal/dtest"
	"github.com/quic-go/quic-go"
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

// NodeConfig is the node configuration for a [NetworkNode].
// Do not confuse this type with the same-named [dragon.NodeConfig].
type NodeConfig struct {
	// This starts as a value of [dragon.DefaultQUICConfig()],
	// but callers are free to modify it.
	QUIC *quic.Config

	// A minimal TLS config.
	// TODO: Some fields are not acceptable to modify; we need to document which.
	TLS *tls.Config

	// The config used to set up the TLS config.
	// Possibly useful if you need to inspect the CA or leaf certificate details.
	CA dcatest.CAConfig

	// There is probably no circumstance where this should be modified,
	// so leave it unexported and require use of ToDragonNodeConfig.
	udpConn *net.UDPConn
}

// ToDragonNodeConfig copies the relevant fields from c
// to a new dragon.NodeConfig.
//
// You must use this method inside the configCreator callback for [NewNetwork],
// as it copies unexported fields from c.
//
// This only populates the UDPConn, QUIC, and TLS fields;
// remaining fields need to be populated manually.
func (c NodeConfig) ToDragonNodeConfig() dragon.NodeConfig {
	return dragon.NodeConfig{
		UDPConn: c.udpConn,
		QUIC:    c.QUIC,
		TLS:     c.TLS,

		AdvertiseAddr: c.udpConn.LocalAddr().String(),
	}
}

// NewDefaultNetwork accepts a testing.T and a set of CA configurations,
// then returns a Network.
//
// It uses default settings for every node;
// if finer control is needed, use [NewNetwork]
// and provide an appropriate configCreator callback.
func NewDefaultNetwork(t *testing.T, ctx context.Context, cfgs ...dcatest.CAConfig) *Network {
	t.Helper()

	return NewNetwork(t, ctx, cfgs, func(_ int, nc NodeConfig) dragon.NodeConfig {
		out := nc.ToDragonNodeConfig()

		// TODO: this should switch to accepting by default.
		out.PeerEvaluator = devaltest.DenyingPeerEvaluator{}
		return out
	})
}

// NewNetwork returns a new network,
// using the configCreator callback to have fine-grained control over the config
// for each created node.
//
// If any error occurs while creating the network,
// t.Fatal is called.
//
// t.Cleanup is used extensively to ensure resources are claned up.
//
// Tests should prefer [NewDefaultNetwork] unless they actually need the fine control.
func NewNetwork(
	t *testing.T,
	ctx context.Context,
	cfgs []dcatest.CAConfig,
	configCreator func(int, NodeConfig) dragon.NodeConfig,
) *Network {
	t.Helper()

	if configCreator == nil {
		panic(errors.New("BUG: must provide configCreator when calling NewNetwork"))
	}

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

			// TODO: this isn't going to work with dynamic certificate sets.
			RootCAs: tp.Pool,
		}

		nc := configCreator(i, NodeConfig{
			udpConn: uc,
			QUIC:    dragon.DefaultQUICConfig(),
			TLS:     &tc,
			CA:      cfgs[i],
		})

		n, err := dragon.NewNode(ctx, log.With("node", i), nc)
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
