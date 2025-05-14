package bci_test

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/breathcast/internal/bci"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestRunAcceptBroadcast_firstUpdate(t *testing.T) {
	t.Run("empty initial state", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var wg sync.WaitGroup
		defer wg.Wait()

		s, sTest := establishedStream(t, ctx)

		haveLeaves := bitset.MustNew(4)

		bci.RunAcceptBroadcast(ctx, dtest.NewLogger(t), bci.AcceptBroadcastConfig{
			WG: &wg,

			Stream:        sTest,
			PacketHandler: new(datagramCollector),

			InitialHaveLeaves: haveLeaves.Clone(),
			AddedLeaves:       dchan.NewMulticast[uint](),

			BitsetSendPeriod: 2 * time.Millisecond, // Arbitrary for test.

			// Not closing dataReady for this test, so it can be nil.
			DataReady: nil,
		})
		defer cancel()

		dec := new(bci.CombinationDecoder)
		got := bitset.MustNew(4)

		// The operation immediately sends its have bitset, which is empty.
		require.NoError(t, dec.ReceiveBitset(s, 5*time.Millisecond, got))
		require.Zero(t, got.Count())
	})

	t.Run("partially filled initial state", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var wg sync.WaitGroup
		defer wg.Wait()

		s, sTest := establishedStream(t, ctx)

		haveLeaves := bitset.MustNew(4)
		haveLeaves.Set(0)
		haveLeaves.Set(2)

		bci.RunAcceptBroadcast(ctx, dtest.NewLogger(t), bci.AcceptBroadcastConfig{
			WG: &wg,

			Stream:        sTest,
			PacketHandler: new(datagramCollector),

			InitialHaveLeaves: haveLeaves.Clone(),
			AddedLeaves:       dchan.NewMulticast[uint](),

			BitsetSendPeriod: 2 * time.Millisecond, // Arbitrary for test.

			// Not closing dataReady for this test, so it can be nil.
			DataReady: nil,
		})
		defer cancel()

		dec := new(bci.CombinationDecoder)
		got := bitset.MustNew(4)

		// The operation immediately sends its have bitset,
		// which matches the initial input.
		require.NoError(t, dec.ReceiveBitset(s, 5*time.Millisecond, got))
		require.True(t, haveLeaves.Equal(got))
	})
}

func TestRunAcceptBroadcast_externalUpdatesShared(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	defer wg.Wait()

	s, sTest := establishedStream(t, ctx)

	haveLeaves := bitset.MustNew(4)

	// Set one bit so we confirm the sent bitsets are only deltas.
	haveLeaves.Set(0)

	al := dchan.NewMulticast[uint]()

	bci.RunAcceptBroadcast(ctx, dtest.NewLogger(t), bci.AcceptBroadcastConfig{
		WG: &wg,

		Stream:        sTest,
		PacketHandler: new(datagramCollector),

		InitialHaveLeaves: haveLeaves.Clone(),
		AddedLeaves:       al,

		BitsetSendPeriod: 5 * time.Millisecond, // Arbitrary for test.

		// Not closing dataReady for this test, so it can be nil.
		DataReady: nil,
	})
	defer cancel()

	dec := new(bci.CombinationDecoder)
	got := bitset.MustNew(4)

	// The operation immediately sends its have bitset.
	require.NoError(t, dec.ReceiveBitset(s, 5*time.Millisecond, got))
	require.Equal(t, uint(1), got.Count())
	require.True(t, got.Test(0))

	// Now we tell the operation that it has a bit set.
	al.Set(3)
	al = al.Next

	require.NoError(t, dec.ReceiveBitset(s, 5*time.Millisecond, got))

	// It is possible that the update was late, so refresh once if necessary.
	if got.None() {
		require.NoError(t, dec.ReceiveBitset(s, 5*time.Millisecond, got))
	}

	require.Equal(t, uint(1), got.Count())
	require.True(t, got.Test(3))
}

func TestRunAcceptBroadcast_syncDatagrams(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	defer wg.Wait()

	s, sTest := establishedStream(t, ctx)

	c := new(datagramCollector)

	bci.RunAcceptBroadcast(ctx, dtest.NewLogger(t), bci.AcceptBroadcastConfig{
		WG: &wg,

		Stream:        sTest,
		PacketHandler: c,

		InitialHaveLeaves: bitset.MustNew(4),
		AddedLeaves:       dchan.NewMulticast[uint](),

		BitsetSendPeriod: 5 * time.Millisecond, // Arbitrary for test.

		// Not closing dataReady for this test, so it can be nil.
		DataReady: nil,
	})
	defer cancel()

	dec := new(bci.CombinationDecoder)
	got := bitset.MustNew(4)

	// The operation immediately sends its have bitset, which is empty.
	require.NoError(t, dec.ReceiveBitset(s, 5*time.Millisecond, got))
	require.Zero(t, got.Count())

	// Now we send a synchronous datagram.
	dg := []byte("some fake datagram content")
	require.NoError(t, bci.SendSyncMissedDatagram(s, 10*time.Millisecond, 0, dg))

	// When the operation calls HandleDatagram,
	// it would normally be relying on feedback from the BroadcastOperation
	// to update a bitset; our mock offers no such feedback.
	// Therefore, wait two bitset updates to ensure we are synchronized
	// and then confirm the presence of the datagram.

	require.NoError(t, dec.ReceiveBitset(s, 5*time.Millisecond, got))
	require.NoError(t, dec.ReceiveBitset(s, 5*time.Millisecond, got))

	// And that means the datagram collector should have captured the value.
	require.Equal(t, dg, c.Get(0))
}

type datagramCollector struct {
	mu  sync.Mutex
	dgs [][]byte
}

func (c *datagramCollector) HandlePacket(_ context.Context, dg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.dgs = append(c.dgs, dg)
	return nil
}

func (c *datagramCollector) Get(idx int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.dgs[idx]
}

// establishedStream returns a pair of streams,
// one for each side of a stream between two hosts in a [dquictest.ListenerSet]
// created inside this helper function
func establishedStream(t *testing.T, ctx context.Context) (left, right quic.Stream) {
	t.Helper()

	ls := dquictest.NewListenerSet(t, ctx, 2)
	c01, c10 := ls.Dial(t, 0, 1)

	// The stream we'll be using in the test.
	s0, err := c01.OpenStream()
	require.NoError(t, err)

	// We have to send something before the stream can be accepted.
	// Normally this would be the broadcast handshake,
	// but we are not including the broadcast operation in this test,
	// so just write one junk byte.
	_, err = s0.Write([]byte{1})
	require.NoError(t, err)

	// Accept the strema.
	s1, err := c10.AcceptStream(ctx)
	require.NoError(t, err)

	// Consume the junk byte so it doesn't affect the operation.
	_, err = io.ReadFull(s1, make([]byte, 1))
	require.NoError(t, err)

	return s0, s1
}
