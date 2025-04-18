package breathcast_test

import (
	"context"
	"io"
	"testing"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/breathcast/breathcasttest"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestProtocol2_allDatagramsSucceed(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fx := breathcasttest.NewProtocolFixture(t, ctx, breathcasttest.ProtocolFixtureConfig{
		Nodes: 2,

		ProtocolID:        0xFE,
		BroadcastIDLength: 3,
	})
	defer cancel()

	// Now The connections are set up, and we can set up the sub-protocols.
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

	bop0, err := fx.Protocols[0].NewOrigination(ctx, breathcast.OriginationConfig{
		BroadcastID: []byte("xyz"),
		AppHeader:   []byte("fake app header"),
		Datagrams:   orig.Chunks,

		NData: uint16(orig.NumData),

		TotalDataSize: len(data),
		ChunkSize:     orig.ChunkSize,
	})
	require.NoError(t, err)
	defer bop0.Wait()
	defer cancel()

	bop1, err := fx.Protocols[1].NewIncomingBroadcast(ctx, breathcast.IncomingBroadcastConfig{
		BroadcastID: []byte("xyz"),
		AppHeader:   []byte("fake app header"),
		NData:       uint16(orig.NumData),
		NParity:     uint16(orig.NumParity),

		Hasher:    bcsha256.Hasher{},
		HashSize:  bcsha256.HashSize,
		HashNonce: nonce,

		RootProofs: orig.RootProof,

		TotalDataSize: len(data),
		ChunkSize:     uint16(orig.ChunkSize),
	})
	require.NoError(t, err)
	defer bop1.Wait()
	defer cancel()

	// Node 0 is going to originate a broadcast to 1.
	c0, c1 := fx.ListenerSet.Dial(t, 0, 1)

	// Ensure that each datagram arrives
	continueCh := make(chan struct{})
	c0 = guaranteedDatagramQCWrapper{
		Ctx:               ctx,
		Connection:        c0,
		IncomingBroadcast: bop1,
		Continue:          continueCh,
	}

	fx.AddConnection(c0, 0, 1)
	fx.AddConnection(c1, 1, 0)

	// Now, the application layer would have to accept the stream from the remote first.
	s, err := c1.AcceptStream(ctx)
	require.NoError(t, err)

	var oneByte [1]byte
	_, err = io.ReadFull(s, oneByte[:])
	require.NoError(t, err)
	require.Equal(t, byte(0xFE), oneByte[0])

	// The incoming stream has the right application header.
	appHeader, err := breathcast.ExtractStreamBroadcastHeader(s, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("fake app header"), appHeader)

	// We accept the broadcast now that we've parsed the app header:
	dtest.NotSending(t, bop1.DataReady())
	require.NoError(t, bop1.AcceptBroadcast(
		ctx,
		dconn.Conn{
			QUIC:  c1,
			Chain: fx.ListenerSet.Leaves[0].Chain,
		},
		s,
	))

	for range orig.NumData - 1 {
		_ = dtest.ReceiveSoon(t, continueCh)
		dtest.NotSending(t, bop1.DataReady())
	}

	// One final signal on the continue channel.
	_ = dtest.ReceiveSoon(t, continueCh)

	// And the data becomes ready.
	_ = dtest.ReceiveSoon(t, bop1.DataReady())

	// Therefore we can read it immediately.
	all, err := io.ReadAll(bop1.Data(ctx))
	require.NoError(t, err)
	require.Equal(t, data, all)
}

type guaranteedDatagramQCWrapper struct {
	quic.Connection
	Ctx               context.Context
	IncomingBroadcast *breathcast.BroadcastOperation
	Continue          chan struct{}
}

func (w guaranteedDatagramQCWrapper) SendDatagram(datagram []byte) error {
	// Block progress before we send the datagram,
	// so the test can synchronize.
	select {
	case <-w.Ctx.Done():
		return w.Ctx.Err()
	case w.Continue <- struct{}{}:
		// Okay.
	}

	go w.IncomingBroadcast.HandleDatagram(w.Ctx, datagram)

	return nil
}

func TestProtocol2_allDatagramsDropped(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fx := breathcasttest.NewProtocolFixture(t, ctx, breathcasttest.ProtocolFixtureConfig{
		Nodes: 2,

		ProtocolID:        0xFE,
		BroadcastIDLength: 3,
	})
	defer cancel()

	// Node 0 is going to originate a broadcast to 1.
	c0, c1 := fx.ListenerSet.Dial(t, 0, 1)

	// Wrap c0 so that datagrams don't go through.
	c0 = dropDatagramQCWrapper{Connection: c0}

	fx.AddConnection(c0, 0, 1)
	fx.AddConnection(c1, 1, 0)

	// Now The connections are set up, and we can set up the sub-protocols.
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

	bop0, err := fx.Protocols[0].NewOrigination(ctx, breathcast.OriginationConfig{
		BroadcastID: []byte("xyz"),
		AppHeader:   []byte("fake app header"),
		Datagrams:   orig.Chunks,

		NData: uint16(orig.NumData),

		TotalDataSize: len(data),
		ChunkSize:     orig.ChunkSize,
	})
	require.NoError(t, err)
	defer bop0.Wait()
	defer cancel()

	bop1, err := fx.Protocols[1].NewIncomingBroadcast(ctx, breathcast.IncomingBroadcastConfig{
		BroadcastID: []byte("xyz"),
		AppHeader:   []byte("fake app header"),
		NData:       uint16(orig.NumData),
		NParity:     uint16(orig.NumParity),

		Hasher:    bcsha256.Hasher{},
		HashSize:  bcsha256.HashSize,
		HashNonce: nonce,

		RootProofs: orig.RootProof,

		TotalDataSize: len(data),
		ChunkSize:     uint16(orig.ChunkSize),
	})
	require.NoError(t, err)
	defer bop1.Wait()
	defer cancel()

	// Now, the application layer would have to accept the stream from the remote first.
	s, err := c1.AcceptStream(ctx)
	require.NoError(t, err)

	var oneByte [1]byte
	_, err = io.ReadFull(s, oneByte[:])
	require.NoError(t, err)
	require.Equal(t, byte(0xFE), oneByte[0])

	// The incoming stream has the right application header.
	appHeader, err := breathcast.ExtractStreamBroadcastHeader(s, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("fake app header"), appHeader)

	// We accept the broadcast now that we've parsed the app header:
	dtest.NotSending(t, bop1.DataReady())
	require.NoError(t, bop1.AcceptBroadcast(
		ctx,
		dconn.Conn{
			QUIC:  c1,
			Chain: fx.ListenerSet.Leaves[0].Chain,
		},
		s,
	))

	// And the data becomes ready shortly thereafter.
	_ = dtest.ReceiveSoon(t, bop1.DataReady())

	// Therefore we can read it immediately.
	all, err := io.ReadAll(bop1.Data(ctx))
	require.NoError(t, err)
	require.Equal(t, data, all)
}

type dropDatagramQCWrapper struct {
	quic.Connection
}

func (w dropDatagramQCWrapper) SendDatagram([]byte) error {
	return nil
}
