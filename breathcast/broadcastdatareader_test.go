package breathcast_test

import (
	"context"
	"testing"
	"testing/iotest"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestBroadcastOperation_origination_reader(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up an origination and a protocol.
	// We don't need any connections for this.
	data := dtest.RandomDataForTest(t, 16*1024)
	nonce := []byte("nonce")
	orig, err := breathcast.PrepareOrigination(data, breathcast.PrepareOriginationConfig{
		MaxChunkSize:    1000,
		ProtocolID:      0xFE,
		BroadcastID:     []byte("xyz"),
		ParityRatio:     0.1,
		HeaderProofTier: 1,
		Hasher:          bcsha256.Hasher{},
		HashSize:        bcsha256.HashSize,
		Nonce:           nonce,
	})
	require.NoError(t, err)

	p := breathcast.NewProtocol2(ctx, dtest.NewLogger(t), breathcast.Protocol2Config{
		ConnectionChanges: dchan.NewMulticast[dconn.Change](),
		ProtocolID:        0xFE,
		BroadcastIDLength: 3,
	})

	bop, err := p.NewOrigination(ctx, breathcast.OriginationConfig{
		BroadcastID: []byte("xyz"),
		AppHeader:   []byte("fake app header"),
		Datagrams:   orig.Chunks,

		NData: uint16(orig.NumData),

		TotalDataSize: len(data),
		ChunkSize:     orig.ChunkSize,
	})
	require.NoError(t, err)
	defer bop.Wait()
	defer cancel()

	require.NoError(t, iotest.TestReader(bop.Data(ctx), data))
}
