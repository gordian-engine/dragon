package dprotoi_test

import (
	"bytes"
	"testing"

	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/internal/dprotoi"
	"github.com/stretchr/testify/require"
)

func TestShuffleMessage_roundTrip(t *testing.T) {
	t.Parallel()

	ca1, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)
	leaf1, err := ca1.CreateLeafCert(dcerttest.LeafConfig{
		DNSNames: []string{"leaf1.example"},
	})
	require.NoError(t, err)

	aa1, err := leaf1.AddressAttestation("leaf1.example")
	require.NoError(t, err)

	ca2, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)
	leaf2, err := ca2.CreateLeafCert(dcerttest.LeafConfig{
		DNSNames: []string{"leaf2.example"},
	})
	require.NoError(t, err)

	aa2, err := leaf2.AddressAttestation("leaf2.example")
	require.NoError(t, err)

	msg := dprotoi.ShuffleMessage{
		Entries: []dprotoi.ShuffleEntry{
			{
				AA:    aa1,
				Chain: leaf1.Chain,
			},
			{
				AA:    aa2,
				Chain: leaf2.Chain,
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, msg.EncodeBare(&buf))

	var got dprotoi.ShuffleMessage
	require.NoError(t, got.Decode(&buf))

	require.Equal(t, msg, got)
}
