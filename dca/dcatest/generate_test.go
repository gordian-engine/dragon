package dcatest_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"dragon.example/dragon/dca/dcatest"
	"github.com/stretchr/testify/require"
)

func TestGenerateCA_valid(t *testing.T) {
	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()

		cfg := dcatest.FastConfig()
		require.Equal(t, dcatest.Ed25519KeyType, cfg.KeyType)
		ca, err := dcatest.GenerateCA(cfg)
		require.NoError(t, err)

		leaf, err := ca.CreateLeafCert(dcatest.LeafConfig{
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
	})
}
