package breathcast_test

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/breathcast/breathcasttest"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestProtocol_allDatagramsSucceed(t *testing.T) {
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
		Packets:     orig.Packets,

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

	// Ensure that each datagram arrives.
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

	bid, err := fx.Protocols[1].ExtractStreamBroadcastID(s, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("xyz"), bid)

	// The incoming stream has the right application header.
	appHeader, err := breathcast.ExtractStreamApplicationHeader(s, nil)
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

	go w.IncomingBroadcast.HandlePacket(w.Ctx, datagram)

	return nil
}

// This test covers that full datagrams are regenerated
// when parity datagrams are used.
// This is a particular edge case in that the underlying data
// is straightforward to reconstitute,
// but there is work involved in generating the rest of the datagram.
func TestProtocol_onlyFirstDatagramDropped(t *testing.T) {
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
		ParityRatio:     0.4, // Make sure we have a few extra parity chunks.
		HeaderProofTier: 1,
		Hasher:          bcsha256.Hasher{},
		HashSize:        bcsha256.HashSize,
		Nonce:           nonce,
	})
	require.NoError(t, err)

	bop0, err := fx.Protocols[0].NewOrigination(ctx, breathcast.OriginationConfig{
		BroadcastID: []byte("xyz"),
		AppHeader:   []byte("fake app header"),
		Packets:     orig.Packets,

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
	c0 = &dropFirstDatagramQCWrapper{
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

	bid, err := fx.Protocols[1].ExtractStreamBroadcastID(s, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("xyz"), bid)

	// The incoming stream has the right application header.
	appHeader, err := breathcast.ExtractStreamApplicationHeader(s, nil)
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

	// Full count of original data because the first datagram is dropped.
	// Therefore we use one parity chunk to handle the missing data chunk.
	for range orig.NumData {
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

type dropFirstDatagramQCWrapper struct {
	quic.Connection
	Ctx               context.Context
	IncomingBroadcast *breathcast.BroadcastOperation
	Continue          chan struct{}
	sentSoFar         int64
}

func (w *dropFirstDatagramQCWrapper) SendDatagram(datagram []byte) error {
	// Block progress before we send the datagram,
	// so the test can synchronize.
	var sent int64
	select {
	case <-w.Ctx.Done():
		return w.Ctx.Err()
	case w.Continue <- struct{}{}:
		sent = atomic.AddInt64(&w.sentSoFar, 1)
	}

	if sent > 1 {
		go w.IncomingBroadcast.HandlePacket(w.Ctx, datagram)
	}

	return nil
}

func TestProtocol_allDatagramsDropped(t *testing.T) {
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
		Packets:     orig.Packets,

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

	bid, err := fx.Protocols[1].ExtractStreamBroadcastID(s, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("xyz"), bid)

	// The incoming stream has the right application header.
	appHeader, err := breathcast.ExtractStreamApplicationHeader(s, nil)
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

func TestProtocol_Relay_datagramsForwarded(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// In this setup, node 0 is the originator, broadcasting directly to 1.
	// Then 1 has a connection to 2,
	// so datagrams sent from 0 to 1, are then forwarded from 1 to 2.
	fx := breathcasttest.NewProtocolFixture(t, ctx, breathcasttest.ProtocolFixtureConfig{
		Nodes: 3,

		ProtocolID:        0xFE,
		BroadcastIDLength: 3,
	})
	defer cancel()

	// Now the connections are set up, and we can set up the sub-protocols.
	data := dtest.RandomDataForTest(t, 16*1024)
	nonce := []byte("nonce")
	orig, err := breathcast.PrepareOrigination(data, breathcast.PrepareOriginationConfig{
		MaxChunkSize:    1000,
		ProtocolID:      0xFE,
		BroadcastID:     []byte("xyz"),
		ParityRatio:     0.5, // A bunch of parity shards so we can complete via datagrams.
		HeaderProofTier: 1,
		Hasher:          bcsha256.Hasher{},
		HashSize:        bcsha256.HashSize,
		Nonce:           nonce,
	})
	require.NoError(t, err)

	bop0, err := fx.Protocols[0].NewOrigination(ctx, breathcast.OriginationConfig{
		BroadcastID: []byte("xyz"),
		AppHeader:   []byte("fake app header"),
		Packets:     orig.Packets,

		NData: uint16(orig.NumData),

		TotalDataSize: len(data),
		ChunkSize:     orig.ChunkSize,
	})
	require.NoError(t, err)
	defer bop0.Wait()
	defer cancel()

	inCfg := breathcast.IncomingBroadcastConfig{
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
	}

	c01, c10 := fx.ListenerSet.Dial(t, 0, 1)
	c12, c21 := fx.ListenerSet.Dial(t, 1, 2)

	// Ensure datagrams arrive 0->1->2 without being dropped.
	c01 = newLateBoundDatagramQCWrapper(ctx, c01)
	c12 = newLateBoundDatagramQCWrapper(ctx, c12)

	fx.AddConnection(c01, 0, 1)
	fx.AddConnection(c10, 1, 0)
	fx.AddConnection(c12, 1, 2)
	fx.AddConnection(c21, 2, 1)

	// Application layer has to accept remote stream first.
	s01, err := c10.AcceptStream(ctx)
	require.NoError(t, err)

	var oneByte [1]byte
	_, err = io.ReadFull(s01, oneByte[:])
	require.NoError(t, err)
	require.Equal(t, byte(0xFE), oneByte[0])

	bid, err := fx.Protocols[1].ExtractStreamBroadcastID(s01, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("xyz"), bid)

	// The incoming stream has the right application header.
	appHeader, err := breathcast.ExtractStreamApplicationHeader(s01, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("fake app header"), appHeader)

	// We've extracted the application header,
	// so now this protocol instance can create the broadcast operation.
	bop1, err := fx.Protocols[1].NewIncomingBroadcast(ctx, inCfg)
	require.NoError(t, err)
	defer bop1.Wait()
	defer cancel()

	c01.(*lateBoundDatagramQCWrapper).SetOp(bop1)

	// We accept the broadcast now that we've parsed the app header:
	dtest.NotSending(t, bop1.DataReady())
	require.NoError(t, bop1.AcceptBroadcast(
		ctx,
		dconn.Conn{
			QUIC:  c01,
			Chain: fx.ListenerSet.Leaves[0].Chain,
		},
		s01,
	))

	// Now, node 0 should be attempting to send a datagram,
	// but it is blocked on the continue channel.
	// Before allowing the first datagram,
	// ensure that the stream headers are forwarded from 1 to 2.

	s12, err := c21.AcceptStream(ctx)
	require.NoError(t, err)

	// Now validate the input again.
	_, err = io.ReadFull(s12, oneByte[:])
	require.NoError(t, err)
	require.Equal(t, byte(0xFE), oneByte[0])

	bid, err = fx.Protocols[1].ExtractStreamBroadcastID(s12, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("xyz"), bid)

	// The incoming stream has the right application header.
	appHeader, err = breathcast.ExtractStreamApplicationHeader(s12, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("fake app header"), appHeader)

	// We've extracted the application header,
	// so now this protocol instance can create the broadcast operation.
	bop2, err := fx.Protocols[2].NewIncomingBroadcast(ctx, inCfg)
	require.NoError(t, err)
	defer bop2.Wait()
	defer cancel()

	c12.(*lateBoundDatagramQCWrapper).SetOp(bop2)

	// We accept the broadcast now that we've parsed the app header:
	dtest.NotSending(t, bop2.DataReady())
	require.NoError(t, bop2.AcceptBroadcast(
		ctx,
		dconn.Conn{
			QUIC:  c12,
			Chain: fx.ListenerSet.Leaves[1].Chain,
		},
		s12,
	))

	// Now we have a chain of broadcasts.
	// So unblock the originator's first datagram:
	cont01 := c01.(*lateBoundDatagramQCWrapper).Continue

	// Then unblock the relayer's first datagram.
	cont12 := c12.(*lateBoundDatagramQCWrapper).Continue

	// One datagram short of reconstruction.
	for range orig.NumData - 1 {
		dtest.SendSoon(t, cont01, struct{}{})
		dtest.SendSoon(t, cont12, struct{}{})
	}

	dtest.NotSending(t, bop1.DataReady())
	dtest.NotSending(t, bop2.DataReady())

	t.Skip("TODO: finish handling completed data in outgoing relay")

	dtest.SendSoon(t, cont01, struct{}{})
	dtest.SendSoon(t, cont12, struct{}{})

	_ = dtest.ReceiveSoon(t, bop1.DataReady())
	_ = dtest.ReceiveSoon(t, bop2.DataReady())

	time.Sleep(5 * time.Millisecond)
}

// lateBoundDatagramQCWrapper wraps a QUIC connection
// providing a SendDatagram method that directly calls
// HandleDatagram on a separate BroadcastOperation.
//
// It is "late bound" differing from [guaranteedDatagramQCWrapper]
// because in some tests we do not want the BroadcastOperation
// to be created before the stream is opened.
type lateBoundDatagramQCWrapper struct {
	quic.Connection
	Continue chan struct{}

	ctx context.Context

	opReady chan *breathcast.BroadcastOperation
	op      *breathcast.BroadcastOperation
}

func newLateBoundDatagramQCWrapper(
	ctx context.Context,
	conn quic.Connection,
) *lateBoundDatagramQCWrapper {
	return &lateBoundDatagramQCWrapper{
		Connection: conn,

		Continue: make(chan struct{}),

		ctx: ctx,

		// 1-buffered so SetOp doesn't block.
		opReady: make(chan *breathcast.BroadcastOperation, 1),
	}
}

func (w *lateBoundDatagramQCWrapper) SetOp(op *breathcast.BroadcastOperation) {
	select {
	case <-w.ctx.Done():
		return
	case w.opReady <- op:
		// Don't close the channel in this goroutine;
		// the first receiver in SendDatagram closes the channel,
		// after they have assigned to w.op.
	}
}

func (w *lateBoundDatagramQCWrapper) SendDatagram(datagram []byte) error {
	var op *breathcast.BroadcastOperation
	select {
	case <-w.ctx.Done():
		return w.ctx.Err()
	case x, ok := <-w.opReady:
		if ok {
			w.op = x
			close(w.opReady)
			op = x
		} else {
			op = w.op
		}
	}

	// Block progress before we send the datagram,
	// so the test can synchronize.
	select {
	case <-w.ctx.Done():
		return w.ctx.Err()
	case _ = <-w.Continue:
		// Okay.
	}

	go op.HandlePacket(w.ctx, datagram)

	return nil
}
