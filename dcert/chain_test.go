package dcert_test

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/stretchr/testify/require"
)

func TestNewChainFormCerts_nilIntermediate(t *testing.T) {
	t.Parallel()

	ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)
	leaf, err := ca.CreateLeafCert(dcerttest.LeafConfig{
		DNSNames: []string{"leaf.example"},
	})
	require.NoError(t, err)

	chain, err := dcert.NewChainFromCerts(
		[]*x509.Certificate{
			leaf.Cert,
			ca.Cert,
		},
	)
	require.NoError(t, err)

	require.Nil(t, chain.Intermediate)
}

func TestChain_roundTrip(t *testing.T) {
	t.Run("without intermediates", func(t *testing.T) {
		t.Parallel()

		ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
		require.NoError(t, err)
		leaf, err := ca.CreateLeafCert(dcerttest.LeafConfig{
			DNSNames: []string{"leaf.example"},
		})
		require.NoError(t, err)

		chain := leaf.Chain

		var buf bytes.Buffer
		require.NoError(t, chain.Encode(&buf))

		var got dcert.Chain
		require.NoError(t, got.Decode(&buf))

		require.Equal(t, chain, got)
	})

	// TODO: with intermediates.
}
