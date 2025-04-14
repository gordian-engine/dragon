package breathcast_test

import (
	"context"
	"io"
	"testing"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestProtocol2_NewOrigination(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := dtest.NewLogger(t)
	connChanges0 := dchan.NewMulticast[dconn.Change]()
	connChanges1 := dchan.NewMulticast[dconn.Change]()
	po := breathcast.NewProtocol2(ctx, log.With("side", "originator"), breathcast.Protocol2Config{
		ConnectionChanges: connChanges0,

		ProtocolID: 0x91,

		BroadcastIDLength: 3,
	})
	pa := breathcast.NewProtocol2(ctx, log.With("side", "acceptor"), breathcast.Protocol2Config{
		ConnectionChanges: connChanges1,

		ProtocolID: 0x91,

		BroadcastIDLength: 3,
	})

	defer po.Wait()
	defer pa.Wait()
	defer cancel()

	ls := dquictest.NewListenerSet(t, ctx, 2)

	c0, c1 := ls.Dial(t, 0, 1)

	connChanges0.Set(dconn.Change{
		Conn: dconn.Conn{
			QUIC:  c0,
			Chain: ls.Leaves[1].Chain,
		},
		Adding: true,
	})
	connChanges0 = connChanges0.Next

	connChanges1.Set(dconn.Change{
		Conn: dconn.Conn{
			QUIC:  c1,
			Chain: ls.Leaves[0].Chain,
		},
		Adding: true,
	})
	connChanges1 = connChanges1.Next

	// Prepare an origination for the originator.
	data := dtest.RandomDataForTest(t, 16*1024)
	nonce := []byte("nonce")
	orig, err := breathcast.PrepareOrigination(data, breathcast.PrepareOriginationConfig{
		MaxChunkSize:    1000,
		ProtocolID:      0x91,
		OperationHeader: []byte("xyz"),
		ParityRatio:     0.1,
		HeaderProofTier: 1,
		Hasher:          bcsha256.Hasher{},
		HashSize:        bcsha256.HashSize,
		Nonce:           nonce,
	})
	require.NoError(t, err)

	bop0, err := po.NewOrigination(ctx, breathcast.OriginationConfig{
		BroadcastID: []byte("xyz"),
		AppHeader:   []byte("fake app header"),
		Datagrams:   orig.Chunks,
	})
	require.NoError(t, err)
	defer bop0.Wait()
	defer cancel()

	// Now we have to imitate the accepting application,
	// and accept the new broadcast stream.
	s, err := c1.AcceptStream(ctx)
	require.NoError(t, err)

	var oneByte [1]byte
	_, err = io.ReadFull(s, oneByte[:])
	require.NoError(t, err)
	require.Equal(t, byte(0x91), oneByte[0])

	appHeader, err := breathcast.ExtractStreamBroadcastHeader(s, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("fake app header"), appHeader)
	t.SkipNow()
}
