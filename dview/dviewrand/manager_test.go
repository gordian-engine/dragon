package dviewrand_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/rand/v2"
	"testing"

	"dragon.example/dragon/dca/dcatest"
	"dragon.example/dragon/dview"
	"dragon.example/dragon/dview/dviewrand"
	"dragon.example/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestManager_ConsiderJoin(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca, err := dcatest.GenerateCA(dcatest.FastConfig())
	require.NoError(t, err)

	leaf1, err := ca.CreateLeafCert(dcatest.LeafConfig{
		DNSNames: []string{"leaf1.example"},
	})
	require.NoError(t, err)

	leaf2, err := ca.CreateLeafCert(dcatest.LeafConfig{
		DNSNames: []string{"leaf2.example"},
	})
	require.NoError(t, err)

	m := managerFixture(t, 8, 32)

	p1 := dview.ActivePeer{
		// Some internal knowledge here that the dviewrand.Manager
		// only inspects this one field of TLS,
		// and does not inspect either address.
		TLS: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				leaf1.Cert,
				ca.Cert,
			},
		},
	}

	// First consider join is accepted because we don't have anything to conflict with it.
	jd, err := m.ConsiderJoin(ctx, p1)
	require.NoError(t, err)
	require.Equal(t, dview.AcceptJoinDecision, jd)

	evicted, err := m.AddPeering(ctx, p1)
	require.NoError(t, err)
	require.Nil(t, evicted) // There was nothing to evict.

	p2 := dview.ActivePeer{
		TLS: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				leaf2.Cert,
				ca.Cert,
			},
		},
	}

	// Now this second consider join is denied
	// because this peer has the same CA source.
	jd, err = m.ConsiderJoin(ctx, p2)
	require.NoError(t, err)
	require.Equal(t, dview.DisconnectAndForwardJoinDecision, jd)
}

func managerFixture(t *testing.T, aSize, pSize int) *dviewrand.Manager {
	t.Helper()

	log := dtest.NewLogger(t)
	return dviewrand.New(log, dviewrand.Config{
		ActiveViewSize:  aSize,
		PassiveViewSize: pSize,

		// Use the sizes as the random seeds,
		// just so the behavior within a test is predictable.
		RNG: rand.New(rand.NewPCG(uint64(aSize), uint64(pSize))),
	})
}
