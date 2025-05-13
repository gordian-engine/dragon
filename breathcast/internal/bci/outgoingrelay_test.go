package bci_test

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
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

func TestRunOutgoingRelay_handshake(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0xAA
	broadcastID := []byte("test")
	appHeader := []byte("dummy app header")

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, 0x01, appHeader)

	fx := NewOutgoingRelayFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		3, 1,
	)
	fx.Cfg.Datagrams[0] = []byte("\xAAtestdatagram 0")
	fx.Cfg.InitialHaveDatagrams.Set(0)

	cHost, cClient := fx.ListenerSet.Dial(t, 0, 1)

	fx.Run(t, ctx, nil, cHost)

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

	// Have the client connection receive a datagram,
	// which should only work after the handshake (I think?).
	dgCtx, dgCancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer dgCancel()
	dg, err := cClient.ReceiveDatagram(dgCtx)
	require.NoError(t, err)
	require.Equal(t, fx.Cfg.Datagrams[0], dg)
}

func TestRunOutgoingRelay_redundantDatagramNotSent(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0xAA
	broadcastID := []byte("test")
	appHeader := []byte("dummy app header")

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, 0x01, appHeader)

	fx := NewOutgoingRelayFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		3, 1,
	)
	fx.Cfg.Datagrams[0] = []byte("\xAAtestdatagram 0")
	fx.Cfg.InitialHaveDatagrams.Set(0)

	cHost, cClient := fx.ListenerSet.Dial(t, 0, 1)

	fx.Run(t, ctx, nil, cHost)

	s, err := cClient.AcceptStream(ctx)
	require.NoError(t, err)

	pid, bid, gotAH, _ := parseHeader(t, s, len(broadcastID))
	require.Equal(t, protocolID, pid)
	require.Equal(t, broadcastID, bid)
	require.Equal(t, appHeader, gotAH)

	// For the client side of the handshake,
	// indicate that we already have the zeroth datagram.
	var ce bci.CombinationEncoder
	cbs := bitset.MustNew(4)
	cbs.Set(0)
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// Short timeout to receive a datagram.
	// We expect to not receive one, because we advertised
	// that we have the same bits as the sender.
	dgCtx, dgCancel := context.WithTimeout(ctx, 25*time.Millisecond)
	defer dgCancel()
	_, err = cClient.ReceiveDatagram(dgCtx)
	require.Error(t, err)
	require.ErrorIs(t, err, dgCtx.Err())
}

func TestRunOutgoingRelay_forwardNewDatagram(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0xAA
	broadcastID := []byte("test")
	appHeader := []byte("dummy app header")

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, 0x01, appHeader)

	fx := NewOutgoingRelayFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		3, 1,
	)

	// Mark the first datagram as present,
	// so we can synchronize on sending that out first.
	fx.Cfg.Datagrams[0] = []byte("\xAAtestdatagram 0")
	fx.Cfg.InitialHaveDatagrams.Set(0)

	// The operation is running on the "host" side of the connection.
	cHost, cClient := fx.ListenerSet.Dial(t, 0, 1)
	cWH := &blockingSendDatagram{
		Connection: cHost,
		Ctx:        ctx,
		Out:        make(chan []byte),
	}
	fx.Run(t, ctx, nil, cWH)

	s, err := cClient.AcceptStream(ctx)
	require.NoError(t, err)

	pid, bid, gotAH, _ := parseHeader(t, s, len(broadcastID))
	require.Equal(t, protocolID, pid)
	require.Equal(t, broadcastID, bid)
	require.Equal(t, appHeader, gotAH)

	// For the client side of the handshake,
	// indicate we don't have any data yet.
	var ce bci.CombinationEncoder
	cbs := bitset.MustNew(4)
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// If we are able to force a datagram continue,
	// then we are synchronized with the host's main loop.
	d0 := dtest.ReceiveSoon(t, cWH.Out)
	require.Equal(t, fx.Cfg.Datagrams[0], d0)

	// Now we indicate that the next datagram is available to the host.
	// It would have arrived from a separate peer somehow.
	ad := fx.Cfg.NewAvailableDatagrams
	ad.Set(1)
	ad = ad.Next

	// Then if we are able to send another continue signal,
	// the host tried to send the datagram.
	d1 := dtest.ReceiveSoon(t, cWH.Out)
	require.Equal(t, fx.Cfg.Datagrams[1], d1)
}

func TestRunOutgoingRelay_missedDatagramSentReliably(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0xAA
	broadcastID := []byte("test")
	appHeader := []byte("dummy app header")

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, 0x01, appHeader)

	fx := NewOutgoingRelayFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		3, 1,
	)

	// Mark the first datagram as present,
	// so we can synchronize on sending that out first.
	fx.Cfg.Datagrams[0] = []byte("\xAAtestdatagram 0")
	fx.Cfg.InitialHaveDatagrams.Set(0)

	// The operation is running on the "host" side of the connection.
	cHost, cClient := fx.ListenerSet.Dial(t, 0, 1)
	hostDGs := dchan.NewMulticast[[]byte]()
	cHW := &dquictest.MulticastingDatagramSender{
		Connection: cHost,
		Multicast:  hostDGs,
	}
	fx.Run(t, ctx, nil, cHW)

	s, err := cClient.AcceptStream(ctx)
	require.NoError(t, err)

	pid, bid, gotAH, _ := parseHeader(t, s, len(broadcastID))
	require.Equal(t, protocolID, pid)
	require.Equal(t, broadcastID, bid)
	require.Equal(t, appHeader, gotAH)

	// For the client side of the handshake,
	// indicate we don't have any data yet.
	var ce bci.CombinationEncoder
	cbs := bitset.MustNew(4)
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// Now the host should send that datagram,
	// and we need to synchronize on that send.
	_ = dtest.ReceiveSoon(t, hostDGs.Ready)
	gotDG := hostDGs.Val
	hostDGs = hostDGs.Next
	require.Equal(t, fx.Cfg.Datagrams[0], gotDG)

	// Now we are going to send two empty bit sets in a row.
	// This tells the host that we never got the datagram.
	// We shouldn't need a delay in between.
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// Next, the host sends the 1-byte sync message ID and the datagram.
	require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	buf := make([]byte, 1+4+len(fx.Cfg.Datagrams[0]))
	_, err = io.ReadFull(s, buf)
	require.NoError(t, err)
	require.Equal(t, byte(1), buf[0])

	chunkID := binary.BigEndian.Uint16(buf[1:3])
	require.Zero(t, chunkID)

	sz := binary.BigEndian.Uint16(buf[3:5])
	require.Equal(t, len(fx.Cfg.Datagrams[0]), int(sz))

	require.Equal(t, fx.Cfg.Datagrams[0], buf[5:])
}

func TestRunOutgoingRelay_missedDatagrams_staggered(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0xAA
	broadcastID := []byte("test")
	appHeader := []byte("dummy app header")

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, 0x01, appHeader)

	fx := NewOutgoingRelayFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		3, 1,
	)

	// Mark the first datagram as present,
	// so we can synchronize on sending that out first.
	fx.Cfg.Datagrams[0] = []byte("\xAAtestdatagram 0")
	fx.Cfg.InitialHaveDatagrams.Set(0)

	// The operation is running on the "host" side of the connection.
	cHost, cClient := fx.ListenerSet.Dial(t, 0, 1)
	hostDGs := dchan.NewMulticast[[]byte]()
	cHW := &dquictest.MulticastingDatagramSender{
		Connection: cHost,
		Multicast:  hostDGs,
	}
	fx.Run(t, ctx, nil, cHW)

	s, err := cClient.AcceptStream(ctx)
	require.NoError(t, err)

	pid, bid, gotAH, _ := parseHeader(t, s, len(broadcastID))
	require.Equal(t, protocolID, pid)
	require.Equal(t, broadcastID, bid)
	require.Equal(t, appHeader, gotAH)

	// For the client side of the handshake,
	// indicate we don't have any data yet.
	var ce bci.CombinationEncoder
	cbs := bitset.MustNew(4)
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// Now the host should send that datagram,
	// and we need to synchronize on that send.
	_ = dtest.ReceiveSoon(t, hostDGs.Ready)
	gotDG := hostDGs.Val
	hostDGs = hostDGs.Next
	require.Equal(t, fx.Cfg.Datagrams[0], gotDG)

	// Now we send one empty delta update.
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// Here is the tricky part.
	// We don't have a proper synchronization point for detecting when
	// the relay operation has handled a delta update
	// (at least one that doesn't result in a sync datagram).
	// So we put in a short sleep here
	// which ought to work much of the time.
	time.Sleep(2 * time.Millisecond)

	// Then the host gets a new datagram.
	fx.Cfg.Datagrams[1] = []byte("\xAAtestdatagram 1")
	nad := fx.Cfg.NewAvailableDatagrams
	nad.Set(1)
	nad = nad.Next

	// The host forwards the new datagram to the client,
	// and we can synchronize on that.
	_ = dtest.ReceiveSoon(t, hostDGs.Ready)
	gotDG = hostDGs.Val
	hostDGs = hostDGs.Next
	require.NoError(t, err)
	require.Equal(t, fx.Cfg.Datagrams[1], gotDG)

	// Now the client sends the next delta update, which is still zero.
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// That is two deltas without acknowledging the first datagram.
	require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	buf := make([]byte, 1+4+len(fx.Cfg.Datagrams[0]))
	_, err = io.ReadFull(s, buf)
	require.NoError(t, err)
	require.Equal(t, byte(1), buf[0])

	chunkID := binary.BigEndian.Uint16(buf[1:3])
	require.Zero(t, chunkID)

	sz := binary.BigEndian.Uint16(buf[3:5])
	require.Equal(t, len(fx.Cfg.Datagrams[0]), int(sz))

	require.Equal(t, fx.Cfg.Datagrams[0], buf[5:])

	// Do a short read attempt, and it must time out.
	require.NoError(t, s.SetReadDeadline(time.Now().Add(2*time.Millisecond)))
	n, err := io.ReadFull(s, buf[:])
	require.Error(t, err)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Zero(t, n)

	// And now we send another delta update,
	// this time including the sync datagram index we received.
	cbs.Set(0)
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// That update causes another sync update, finally.
	require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = io.ReadFull(s, buf)
	require.NoError(t, err)
	require.Equal(t, byte(1), buf[0])

	chunkID = binary.BigEndian.Uint16(buf[1:3])
	require.Equal(t, uint16(1), chunkID)

	sz = binary.BigEndian.Uint16(buf[3:5])
	require.Equal(t, len(fx.Cfg.Datagrams[0]), int(sz))

	require.Equal(t, fx.Cfg.Datagrams[1], buf[5:])
}

func parseHeader(
	t *testing.T,
	s quic.ReceiveStream,
	bidLen int,
) (
	protocolID byte,
	broadcastID []byte,
	appHeader []byte,
	ratio byte,
) {
	t.Helper()

	require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))

	var pid [1]byte
	_, err := io.ReadFull(s, pid[:])
	require.NoError(t, err)

	bid := make([]byte, bidLen)
	_, err = io.ReadFull(s, bid)
	require.NoError(t, err)

	var rat [1]byte
	_, err = io.ReadFull(s, rat[:])
	require.NoError(t, err)

	var sz [2]byte
	_, err = io.ReadFull(s, sz[:])
	require.NoError(t, err)
	gotSize := binary.BigEndian.Uint16(sz[:])

	ah := make([]byte, gotSize)
	_, err = io.ReadFull(s, ah)
	require.NoError(t, err)

	return pid[0], bid, ah, rat[0]
}

// OutgoingRelayFixture is a fixture providing most of the configuration
// for calling [bci.RunOutgoingRelay].
//
// Use [NewOutgoingRelayFixture] to prepare the fixture;
// make adjustments to values on the config if necessary;
// then call [*OutgoingRelayFixture.Run].
//
// The most common config adjustments would be
// modifying the initial datagrams and the corresponding bitset,
type OutgoingRelayFixture struct {
	Cfg bci.OutgoingRelayConfig

	ListenerSet *dquictest.ListenerSet

	DataReady chan struct{}
}

// NewOutgoingRelayFixture returns a fixture reflecting
// the given arguments.
func NewOutgoingRelayFixture(
	t *testing.T,
	ctx context.Context,
	nListeners int,
	protocolHeader bci.ProtocolHeader,
	appHeader []byte,
	nData, nParity uint16,
) *OutgoingRelayFixture {
	t.Helper()

	dataReady := make(chan struct{})

	cfg := bci.OutgoingRelayConfig{
		WG: new(sync.WaitGroup),

		// Conn injected in Run call.

		ProtocolHeader: protocolHeader,
		AppHeader:      appHeader,

		Datagrams: make([][]byte, nData+nParity),

		InitialHaveDatagrams: bitset.MustNew(uint(nData + nParity)),

		NewAvailableDatagrams: dchan.NewMulticast[uint](),

		DataReady: dataReady,

		NData:   nData,
		NParity: nParity,
	}

	return &OutgoingRelayFixture{
		Cfg: cfg,

		ListenerSet: dquictest.NewListenerSet(t, ctx, nListeners),

		DataReady: dataReady,
	}
}

// Run calls [bci.RunOutgoingRelay].
//
// If the log parameter is nil, a reasonable default is used.
// The conn argument is required.
func (f *OutgoingRelayFixture) Run(
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

	bci.RunOutgoingRelay(tCtx, log, f.Cfg)
}

type blockingSendDatagram struct {
	quic.Connection

	Ctx context.Context
	Out chan []byte
}

func (b *blockingSendDatagram) SendDatagram(d []byte) error {
	select {
	case <-b.Ctx.Done():
		return b.Ctx.Err()
	case b.Out <- d:
		return nil
	}
}
