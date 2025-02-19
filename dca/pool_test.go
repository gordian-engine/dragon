package dca_test

import (
	"crypto/x509"
	"testing"

	"github.com/gordian-engine/dragon/dca"
	"github.com/gordian-engine/dragon/dca/dcatest"
	"github.com/stretchr/testify/require"
)

func TestPool_NotifyRemoval(t *testing.T) {
	t.Parallel()

	ca1, err := dcatest.GenerateCA(dcatest.FastConfig())
	require.NoError(t, err)

	ca2, err := dcatest.GenerateCA(dcatest.FastConfig())
	require.NoError(t, err)

	t.Run("returns nil for unrecognized certificate", func(t *testing.T) {
		t.Parallel()

		p := dca.NewPoolFromCerts([]*x509.Certificate{ca1.Cert})
		require.Nil(t, p.NotifyRemoval(ca2.Cert))
	})

	t.Run("notifies channel only when missing from updated set", func(t *testing.T) {
		t.Parallel()

		p := dca.NewPoolFromCerts([]*x509.Certificate{ca1.Cert})
		ch := p.NotifyRemoval(ca1.Cert)
		require.NotNil(t, ch)

		p.UpdateCAs([]*x509.Certificate{ca1.Cert, ca2.Cert})
		select {
		case <-ch:
			t.Fatal("channel should not have been closed")
		default:
			// Okay.
		}

		p.UpdateCAs([]*x509.Certificate{ca2.Cert})
		select {
		case <-ch:
			// Okay.
		default:
			t.Fatal("channel should have been closed after certificate removal")
		}
	})

	t.Run("multiple notifications are the same underlying channel", func(t *testing.T) {
		t.Parallel()

		p := dca.NewPoolFromCerts([]*x509.Certificate{ca1.Cert, ca2.Cert})
		ch1a := p.NotifyRemoval(ca1.Cert)
		ch1b := p.NotifyRemoval(ca1.Cert)

		ch2 := p.NotifyRemoval(ca2.Cert)
		require.NotNil(t, ch2)

		require.Equal(t, ch1a, ch1b)
		require.NotEqual(t, ch1a, ch2)
	})
}
