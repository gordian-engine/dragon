package daddr_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/daddr"
	"github.com/stretchr/testify/require"
)

func TestAddressAttestation_roundTrip(t *testing.T) {
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
