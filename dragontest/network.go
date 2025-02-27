package dragontest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"testing"

	"github.com/gordian-engine/dragon"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/dview/dviewrand"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// Network contains a collection of NetworkNode values,
// to simplify tests that require multiple nodes.
type Network struct {
	Log *slog.Logger

	Nodes []NetworkNode

	Chains []dcert.Chain
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
	// Possibly useful if you need to inspect the CAConfig or leaf certificate details.
	CAConfig dcerttest.CAConfig

	// The actual CA used for the node config.
	// Useful if you need to create sibling leaves, intermediate CAs, etc.
	CA *dcerttest.CA

	// Initial trusted CAs to set on the outgoing [dragon.NodeConfig].
	TrustedCAs []*x509.Certificate

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

		InitialTrustedCAs: c.TrustedCAs,

		// TODO: we should expose this somehow,
		// so a test can manually trigger a shuffle if needed.
		ShuffleSignal: make(chan struct{}),
	}
}

// NewDefaultNetwork accepts a testing.T and a set of CA configurations,
// then returns a Network.
//
// It uses default settings for every node;
// if finer control is needed, use [NewNetwork]
// and provide an appropriate configCreator callback.
func NewDefaultNetwork(t *testing.T, ctx context.Context, cfgs ...dcerttest.CAConfig) *Network {
	t.Helper()

	log := dtest.NewLogger(t)

	return NewNetwork(t, ctx, cfgs, func(_ int, nc NodeConfig) dragon.NodeConfig {
		out := nc.ToDragonNodeConfig()

		// TODO: this should switch to accepting by default.
		out.ViewManager = dviewrand.New(log.With("node_sys", "view_manager"), dviewrand.Config{
			ActiveViewSize:  len(cfgs),
			PassiveViewSize: 2 * len(cfgs),

			// Test name length is random enough for this seed.
			// More importantly, it's reproducible on every run.
			RNG: rand.New(rand.NewPCG(uint64(len(t.Name())), 0)),
		})
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
	cfgs []dcerttest.CAConfig,
	configCreator func(int, NodeConfig) dragon.NodeConfig,
) *Network {
	t.Helper()

	if configCreator == nil {
		panic(errors.New("BUG: must provide configCreator when calling NewNetwork"))
	}

	log := dtest.NewLogger(t)

	cas := make([]*dcerttest.CA, len(cfgs))
	for i, cfg := range cfgs {
		var err error
		cas[i], err = dcerttest.GenerateCA(cfg)
		require.NoError(t, err)
	}

	nodes := make([]NetworkNode, len(cfgs))
	chains := make([]dcert.Chain, len(cfgs))
	for i, ca := range cas {
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
		l, err := ca.CreateLeafCert(dcerttest.LeafConfig{
			DNSNames: []string{"localhost"},
		})
		require.NoError(t, err)
		chains[i] = l.Chain

		tc := tls.Config{
			// The certificate this client presents.
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{l.Cert.Raw},
					PrivateKey:  l.PrivKey,

					// Not strictly necessary to set the leaf field in general,
					// but the Node in particular requires it to be set properly.
					Leaf: l.Cert,
				},
			},

			ClientAuth: tls.RequireAndVerifyClientCert,
		}

		initialCACerts := make([]*x509.Certificate, len(cas))
		for i, ca := range cas {
			initialCACerts[i] = ca.Cert
		}
		nc := configCreator(i, NodeConfig{
			udpConn:  uc,
			QUIC:     dragon.DefaultQUICConfig(),
			TLS:      &tc,
			CAConfig: cfgs[i],
			CA:       cas[i],

			TrustedCAs: initialCACerts,
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
		Log:    log,
		Nodes:  nodes,
		Chains: chains,
	}
}

func (n *Network) Wait() {
	for _, node := range n.Nodes {
		node.Node.Wait()
	}
}
