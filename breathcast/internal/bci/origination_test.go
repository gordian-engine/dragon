package bci_test

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/breathcast/internal/bci"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestRunOrigination_handshake(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0xAA
	broadcastID := []byte("test")
	appHeader := []byte("dummy app header")

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, 0xFF, appHeader)

	dgs := [][]byte{
		[]byte("datagram0"),
		[]byte("datagram1"),
		[]byte("datagram2"),
		[]byte("datagram3"),
	}

	fx := NewOriginationFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		dgs,
	)

	cOrig, cClient := fx.ListenerSet.Dial(t, 0, 1)
	fx.Run(t, ctx, nil, cOrig)

	s, err := cClient.AcceptStream(ctx)
	require.NoError(t, err)

	pid, bid, gotAH, _ := parseHeader(t, s, len(broadcastID))
	require.Equal(t, protocolID, pid)
	require.Equal(t, broadcastID, bid)
	require.Equal(t, appHeader, gotAH)
}

// If we try to send an origination to a peer who already has all the data,
// they may simply close the connection.
// Ensure that we successfully shut down in that event
// (as opposed to having a goroutine stuck in a blocking read).
func TestRunOrigination_cleanShutdownIfRejected(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0xAA
	broadcastID := []byte("test")
	appHeader := []byte("dummy app header")

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, 0xFF, appHeader)

	dgs := [][]byte{
		[]byte("datagram0"),
		[]byte("datagram1"),
		[]byte("datagram2"),
		[]byte("datagram3"),
	}

	fx := NewOriginationFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		dgs,
	)

	cOrig, cClient := fx.ListenerSet.Dial(t, 0, 1)
	fx.Run(t, ctx, nil, cOrig)

	s, err := cClient.AcceptStream(ctx)
	require.NoError(t, err)

	// We aren't even going to parse anything from the stream, for this test.
	s.CancelRead(bci.GotFullDataErrorCode)
	s.Close()
	s.CancelWrite(bci.GotFullDataErrorCode)

	// Now the deferred cancel and wg.Wait happen.
}

func TestRunOrigination_missedAllUnreliableDatagrams(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0xAA
	broadcastID := []byte("test")
	appHeader := []byte("dummy app header")

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, 0xFF, appHeader)

	dgs := [][]byte{
		[]byte("datagram0"),
		[]byte("datagram1"),
		[]byte("datagram2"),
		[]byte("datagram3"),
	}

	fx := NewOriginationFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		dgs,
	)

	cOrig, cClient := fx.ListenerSet.Dial(t, 0, 1)

	// Run with a connection that drops datagrams.
	fx.Run(t, ctx, nil, dquictest.DatagramDropper{Connection: cOrig})

	s, err := cClient.AcceptStream(ctx)
	require.NoError(t, err)

	pid, bid, gotAH, _ := parseHeader(t, s, len(broadcastID))
	require.Equal(t, protocolID, pid)
	require.Equal(t, broadcastID, bid)
	require.Equal(t, appHeader, gotAH)

	// For the client side of the handshake,
	// just send 4 zero bytes to indicate that we have no datagrams.
	require.NoError(t, s.SetWriteDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = s.Write(make([]byte, 4))
	require.NoError(t, err)

	// Now the first byte we read must be the termination byte.
	var buf [1]byte
	_, err = io.ReadFull(s, buf[:])
	require.NoError(t, err)
	require.Equal(t, byte(0xff), buf[0])

	// We have to respond with our bitset again.
	require.NoError(t, s.SetWriteDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = s.Write(make([]byte, 4))
	require.NoError(t, err)

	// We must get all four datagrams in any order.
	got := bitset.MustNew(4)
	var meta [4]byte
	for range 4 {
		require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
		_, err = io.ReadFull(s, meta[:])
		require.NoError(t, err)

		idx := binary.BigEndian.Uint16(meta[:2])
		sz := binary.BigEndian.Uint16(meta[2:])

		data := make([]byte, sz)
		_, err = io.ReadFull(s, data)
		require.NoError(t, err)

		require.Equal(t, dgs[idx], data)
		require.False(t, got.Test(uint(idx)))
		got.Set(uint(idx))
	}

	// Then the originator must close the stream.
	// We have to attempt a read in order to observe that.
	_, err = io.ReadFull(s, buf[:])
	require.Error(t, err)
	require.ErrorIs(t, err, io.EOF)

	// TODO: should also test that one more write fails appropriately here.
}

type OriginationFixture struct {
	Cfg bci.OriginationConfig

	ListenerSet *dquictest.ListenerSet
}

func NewOriginationFixture(
	t *testing.T,
	ctx context.Context,
	nListeners int,
	protocolHeader bci.ProtocolHeader,
	appHeader []byte,
	datagrams [][]byte,
) *OriginationFixture {
	t.Helper()

	cfg := bci.OriginationConfig{
		WG: new(sync.WaitGroup),

		// Conn injected in Run call.

		ProtocolHeader: protocolHeader,
		AppHeader:      appHeader,

		Datagrams: datagrams,
	}

	return &OriginationFixture{
		Cfg: cfg,

		ListenerSet: dquictest.NewListenerSet(t, ctx, nListeners),
	}
}

// Run calls [bci.RunOrigination].
//
// If the log parameter is nil, a reasonable default is used.
// The conn argument is required.
func (f *OriginationFixture) Run(
	t *testing.T,
	ctx context.Context,
	log *slog.Logger,
	conn quic.Connection,
) {
	t.Helper()

	if log == nil {
		log = dtest.NewLogger(t)
	}

	f.Cfg.Conn = conn

	// Ensure context is canceled at end of test,
	// so caller doesn't need to defer cancel.
	tCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)

	bci.RunOrigination(tCtx, log, f.Cfg)
}
