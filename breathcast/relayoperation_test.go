package breathcast_test

import (
	"context"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestRelayOperation_HandleDatagram_noNetwork(t *testing.T) {
	t.Parallel()

	// Prepare an origination of some random data.
	data := dtest.RandomDataForTest(t, 16*1024)

	nonce := []byte("nonce")
	po, err := breathcast.PrepareOrigination(data, breathcast.PrepareOriginationConfig{
		MaxChunkSize:    1000,
		ProtocolID:      0xFE,
		BroadcastID: []byte{'x'},
		ParityRatio:     0.1,
		HeaderProofTier: 1,
		Hasher:          bcsha256.Hasher{},
		HashSize:        bcsha256.HashSize,
		Nonce:           nonce,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := dtest.NewLogger(t)

	// A pair of listeners so we can have one broadcast to the other.
	ls := dquictest.NewListenerSet(t, ctx, 2)
	_, c1 := ls.Dial(t, 0, 1)

	// Protocol for the 1-side.
	// We are going to fake all the data that the 0-side would be sending.
	// We don't want any real network interactions for this test.
	p1 := breathcast.NewProtocol(ctx, log, breathcast.ProtocolConfig{
		InitialConnections: []dconn.Conn{
			{
				QUIC:  c1,
				Chain: ls.Leaves[0].Chain,
			},
		},
		ProtocolID:        0xFE,
		BroadcastIDLength: 1,
	})
	defer p1.Wait()
	defer cancel()

	// Normally there would be some application-level interactions
	// involving accepting a stream.
	// For this test we'll create the relay operation directly first.
	rop, err := p1.CreateRelayOperation(ctx, ctx, breathcast.RelayOperationConfig{
		BroadcastID: []byte{'x'},
		Nonce:       nonce,

		RootProof: po.RootProof,

		NData:   uint16(po.NumData),
		NParity: uint16(po.NumParity),

		ShardSize: uint16(len(po.Chunks[0])),

		AckTimeout: 50 * time.Millisecond,
	})
	require.NoError(t, err)

	// Now from the prepared origination,
	// we should be able to datagrams successfully.
	// It is "unexpected" that we would be receiving and handling datagrams
	// before a call to (*RelayOperation).AcceptBroadcast,
	// but it is still valid and could happen due to goroutine scheduling.

	require.NoError(t, rop.HandleDatagram(ctx, po.Chunks[0]))

	// Receiving another copy of the same datagram does not cause an error.
	require.NoError(t, rop.HandleDatagram(ctx, po.Chunks[0]))

	// Now all the parity datagrams can be handled without issue.
	for i := po.NumData; i < po.NumData+po.NumParity; i++ {
		require.NoError(t, rop.HandleDatagram(ctx, po.Chunks[i]))
		dtest.NotSending(t, rop.DataReady())
	}

	// Now do a subset of the data chunks.
	// We are still one short after this loop.
	haveShardCount := 1 + po.NumParity
	for i := 1; i < po.NumData-haveShardCount; i++ {
		require.NoError(t, rop.HandleDatagram(ctx, po.Chunks[i]))
		dtest.NotSending(t, rop.DataReady())
	}

	// And with one more data shard, the data is ready.
	require.NoError(t, rop.HandleDatagram(ctx, po.Chunks[po.NumData-haveShardCount+1]))
	// The close happens on a separate goroutine and is unsynchronized.
	_ = dtest.ReceiveSoon(t, rop.DataReady())

	// TODO: assert the actual data content matches.
}

func TestRelayOperation_HandleDatagram_reliableShim(t *testing.T) {
	t.Parallel()

	// Prepare an origination of some random data.
	data := dtest.RandomDataForTest(t, 16*1024)

	nonce := []byte("nonce")
	po, err := breathcast.PrepareOrigination(data, breathcast.PrepareOriginationConfig{
		MaxChunkSize:    1000,
		ProtocolID:      0xFE,
		BroadcastID: []byte{'x'},
		ParityRatio:     0.1,
		HeaderProofTier: 1,
		Hasher:          bcsha256.Hasher{},
		HashSize:        bcsha256.HashSize,
		Nonce:           nonce,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := dtest.NewLogger(t)

	// A pair of listeners so we can have one broadcast to the other.
	ls := dquictest.NewListenerSet(t, ctx, 2)
	c0, c1 := ls.Dial(t, 0, 1)

	// Protocol for the 1-side.
	p1 := breathcast.NewProtocol(ctx, log, breathcast.ProtocolConfig{
		InitialConnections: []dconn.Conn{
			{
				QUIC:  c1,
				Chain: ls.Leaves[0].Chain,
			},
		},
		ProtocolID:        0xFE,
		BroadcastIDLength: 1,
	})
	defer p1.Wait()
	defer cancel()

	// Create the relay operation before setting up the other side of the protocol,
	// so that we can use the test wrapper for reliable datagrams.
	rop, err := p1.CreateRelayOperation(ctx, ctx, breathcast.RelayOperationConfig{
		BroadcastID: []byte{'x'},
		Nonce:       nonce,

		RootProof: po.RootProof,

		NData:   uint16(po.NumData),
		NParity: uint16(po.NumParity),

		ShardSize: uint16(len(po.Chunks[0])),

		AckTimeout: 50 * time.Millisecond,
	})
	require.NoError(t, err)

	// Now that we have the relay operation,
	// we can wrap the connection so that
	// the 0-side protocol instance successfully sends each datagram.
	c0 = &quicWrapperForReliableBroadcastDatagrams{
		Connection:     c0,
		RelayOperation: rop,
	}

	p0 := breathcast.NewProtocol(ctx, log, breathcast.ProtocolConfig{
		InitialConnections: []dconn.Conn{
			{
				QUIC:  c0,
				Chain: ls.Leaves[1].Chain,
			},
		},
		ProtocolID:        0xFE,
		BroadcastIDLength: 1,
	})
	defer p0.Wait()
	defer cancel()

	_, err = p0.Originate(ctx, []byte("dummy header"), po.Chunks[:po.NumData], po.Chunks[po.NumData:])
	require.NoError(t, err)

	// The origination work started on a separate goroutine.
	// Now we need to quickly accept the stream from the receiver side.
	acceptCtx, acceptCancel := context.WithTimeout(ctx, time.Second)
	s, err := c1.AcceptStream(acceptCtx)
	acceptCancel()
	require.NoError(t, err)

	// The origination stream expects us to report we have nothing.
	// We don't need to read the origination details for this test.
	_, err = s.Write([]byte{0})
	require.NoError(t, err)

	_ = dtest.ReceiveSoon(t, rop.DataReady())

	// TODO: assert the actual data content matches.
}

// quicWrapperForReliableBroadcastDatagrams wraps a quic.Connection
// so that SendDatagram directly calls [*breathcast.RelayOperation.HandleDatagram]
// on the wrapper's relay operation.
// This avoids any of the typical uncertainty of datagrams.
type quicWrapperForReliableBroadcastDatagrams struct {
	quic.Connection
	RelayOperation *breathcast.RelayOperation
}

// SendDatagram overrides the embedded SendDatagram,
// so that it reliably and asynchonously calls
// the HandleDatagram method on the given RelayOperation.
func (w *quicWrapperForReliableBroadcastDatagrams) SendDatagram(payload []byte) error {
	go w.RelayOperation.HandleDatagram(context.Background(), payload)
	return nil
}
