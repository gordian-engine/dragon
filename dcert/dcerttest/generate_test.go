package dcerttest_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/stretchr/testify/require"
)

func TestGenerateCA_valid(t *testing.T) {
	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()

		cfg := dcerttest.FastConfig()
		require.Equal(t, dcerttest.Ed25519KeyType, cfg.KeyType)
		ca, err := dcerttest.GenerateCA(cfg)
		require.NoError(t, err)

		leaf, err := ca.CreateLeafCert(dcerttest.LeafConfig{
			DNSNames: []string{"leaf1.example.com"},
		})
		require.NoError(t, err)

		certPool := x509.NewCertPool()
		certPool.AddCert(ca.Cert)

		tlsConf := &tls.Config{
			RootCAs: certPool,
		}

		chains, err := leaf.Cert.Verify(x509.VerifyOptions{
			DNSName: "leaf1.example.com",
			Roots:   tlsConf.RootCAs,
		})
		require.NoError(t, err)
		require.NotEmpty(t, chains)

		require.Len(t, chains[0], 2, "should have had one leaf and one CA")

		require.True(t, chains[0][0].Equal(leaf.Cert))
		require.True(t, chains[0][1].Equal(ca.Cert))

		chain := leaf.Chain
		require.Equal(t, chain.Leaf, leaf.Cert)
		require.Nil(t, chain.Intermediate)
		require.Equal(t, chain.Root, ca.Cert)
	})
}

func TestGenerateCA_singleIntermediate(t *testing.T) {
	t.Parallel()

	ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)

	i, err := ca.CreateIntermediate(dcerttest.FastConfig())
	require.NoError(t, err)

	leaf, err := i.CreateLeafCert(dcerttest.LeafConfig{
		DNSNames: []string{"leaf1.example.com"},
	})
	require.NoError(t, err)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca.Cert)

	iPool := x509.NewCertPool()
	iPool.AddCert(i.Cert)

	tlsConf := &tls.Config{
		RootCAs: rootPool,
	}

	chains, err := leaf.Cert.Verify(x509.VerifyOptions{
		DNSName:       "leaf1.example.com",
		Roots:         tlsConf.RootCAs,
		Intermediates: iPool,
	})
	require.NoError(t, err)
	require.NotEmpty(t, chains)

	require.Len(t, chains[0], 3, "should have had one leaf, one intermediate, and one CA")

	require.True(t, chains[0][0].Equal(leaf.Cert))
	require.True(t, chains[0][1].Equal(i.Cert))
	require.True(t, chains[0][2].Equal(ca.Cert))

	dChain := leaf.Chain
	require.Equal(t, leaf.Cert, dChain.Leaf)
	require.Len(t, dChain.Intermediate, 1)
	require.Equal(t, i.Cert, dChain.Intermediate[0])
	require.Equal(t, ca.Cert, dChain.Root)
}

func TestGenerateCA_twoIntermediates(t *testing.T) {
	t.Parallel()

	ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)

	i1, err := ca.CreateIntermediate(dcerttest.FastConfig())
	require.NoError(t, err)

	i0, err := i1.CreateIntermediate(dcerttest.FastConfig())
	require.NoError(t, err)

	leaf, err := i0.CreateLeafCert(dcerttest.LeafConfig{
		DNSNames: []string{"leaf1.example.com"},
	})
	require.NoError(t, err)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca.Cert)

	iPool := x509.NewCertPool()
	iPool.AddCert(i1.Cert)
	iPool.AddCert(i0.Cert)

	tlsConf := &tls.Config{
		RootCAs: rootPool,
	}

	chains, err := leaf.Cert.Verify(x509.VerifyOptions{
		DNSName:       "leaf1.example.com",
		Roots:         tlsConf.RootCAs,
		Intermediates: iPool,
	})
	require.NoError(t, err)
	require.NotEmpty(t, chains)

	require.Len(t, chains[0], 4, "should have had one leaf, two intermediates, and one CA")

	require.True(t, chains[0][0].Equal(leaf.Cert))
	require.True(t, chains[0][1].Equal(i0.Cert))
	require.True(t, chains[0][2].Equal(i1.Cert))
	require.True(t, chains[0][3].Equal(ca.Cert))

	dChain := leaf.Chain
	require.Equal(t, leaf.Cert, dChain.Leaf)
	require.Len(t, dChain.Intermediate, 2)
	require.Equal(t, i0.Cert, dChain.Intermediate[0])
	require.Equal(t, i1.Cert, dChain.Intermediate[1])
	require.Equal(t, ca.Cert, dChain.Root)
}
