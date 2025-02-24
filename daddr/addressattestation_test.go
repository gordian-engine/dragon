package daddr_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/stretchr/testify/require"
)

func TestAddressAttestation_roundTrip(t *testing.T) {
	t.Parallel()

	aa := daddr.AddressAttestation{
		Addr: "addr.example:12345",

		// Arbitrary timestamp, but needs local so that when we parse it back,
		// it passes the equality chcck.
		Timestamp: time.Date(2025, 2, 21, 20, 15, 33, 0, time.Local),
	}

	// Just use a SHA as a fake signature.
	fakeSig := sha256.Sum256(
		[]byte(fmt.Sprintf("%s %s", aa.Addr, aa.Timestamp.String())))
	aa.Signature = fakeSig[:]

	var buf bytes.Buffer
	require.NoError(t, aa.Encode(&buf))

	var got daddr.AddressAttestation
	require.NoError(t, got.Decode(&buf))

	require.Equal(t, got, aa)
}

func TestAddressAttestation_signature(t *testing.T) {
	t.Parallel()

	aa := daddr.AddressAttestation{
		Addr: "addr.example:12345",

		// Arbitrary timestamp, but needs local so that when we parse it back,
		// it passes the equality chcck.
		Timestamp: time.Date(2025, 2, 21, 20, 15, 33, 0, time.Local),
	}

	ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)

	leaf, err := ca.CreateLeafCert(dcerttest.LeafConfig{
		DNSNames: []string{"leaf1.example"},
	})
	require.NoError(t, err)

	require.NoError(t, aa.SignWithTLSCert(leaf.TLSCert))
	require.NoError(t, aa.VerifySignature(leaf.Cert))

	var buf bytes.Buffer
	require.NoError(t, aa.Encode(&buf))

	var got daddr.AddressAttestation
	require.NoError(t, got.Decode(&buf))

	require.NoError(t, got.VerifySignature(leaf.Cert))
}
