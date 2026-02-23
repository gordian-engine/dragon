package bci_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/breathcast/internal/bci"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dbitset"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/gordian-engine/dragon/internal/dtrace"
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

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, appHeader)

	fx := NewOutgoingRelayFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		3, 1,
	)
	fx.Cfg.Packets[0] = []byte("\xAAtest\x00\x00datagram 0")
	fx.Cfg.InitialHavePackets.Set(0)

	cHost, cClient := fx.ListenerSet.Dial(t, 0, 1)

	fx.Run(t, ctx, nil, cHost)

	s, err := cClient.AcceptStream(ctx)
	require.NoError(t, err)

	pid, bid, gotAH, _ := parseHeader(t, s, len(broadcastID))
	require.Equal(t, protocolID, pid)
	require.Equal(t, broadcastID, bid)
	require.Equal(t, appHeader, gotAH)

	// For the client side of the handshake,
	// indicate that we have no datagrams.
	var enc dbitset.AdaptiveEncoder
	require.NoError(t, enc.SendBitset(s, 50*time.Millisecond, bitset.MustNew(4)))

	// Have the client connection receive a datagram,
	// which should only work after the handshake (I think?).
	dgCtx, dgCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer dgCancel()
	dg, err := cClient.ReceiveDatagram(dgCtx)
	require.NoError(t, err)
	require.Equal(t, fx.Cfg.Packets[0], dg)
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

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, appHeader)

	fx := NewOutgoingRelayFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		3, 1,
	)
	fx.Cfg.Packets[0] = []byte("\xAAtest\x00\x00datagram 0")
	fx.Cfg.InitialHavePackets.Set(0)

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
	var ce dbitset.AdaptiveEncoder
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

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, appHeader)

	fx := NewOutgoingRelayFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		3, 1,
	)

	// Mark the first datagram as present,
	// so we can synchronize on sending that out first.
	fx.Cfg.Packets[0] = []byte("\xAAtest\x00\x00datagram 0")
	fx.Cfg.InitialHavePackets.Set(0)

	// The operation is running on the "host" side of the connection.
	cHost, cClient := fx.ListenerSet.Dial(t, 0, 1)
	cWH := &blockingSendDatagram{
		Conn: cHost,
		Ctx:  ctx,
		Out:  make(chan []byte),
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
	var ce dbitset.AdaptiveEncoder
	cbs := bitset.MustNew(4)
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// If we are able to force a datagram continue,
	// then we are synchronized with the host's main loop.
	d0 := dtest.ReceiveSoon(t, cWH.Out)
	require.Equal(t, fx.Cfg.Packets[0], d0)

	// Now we indicate that the next datagram is available to the host.
	// It would have arrived from a separate peer somehow.
	ad := fx.Cfg.NewAvailablePackets
	ad.Publish(1)
	ad = ad.Next

	// Then if we are able to send another continue signal,
	// the host tried to send the datagram.
	d1 := dtest.ReceiveSoon(t, cWH.Out)
	require.Equal(t, fx.Cfg.Packets[1], d1)
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

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, appHeader)

	fx := NewOutgoingRelayFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		3, 1,
	)

	// Mark the first datagram as present,
	// so we can synchronize on sending that out first.
	fx.Cfg.Packets[0] = []byte("\xAAtest\x00\x00datagram 0")
	fx.Cfg.InitialHavePackets.Set(0)

	// The operation is running on the "host" side of the connection.
	cHost, cClient := fx.ListenerSet.Dial(t, 0, 1)
	hostDGs := dpubsub.NewStream[[]byte]()
	cHW := &dquictest.PubsubDatagramSender{
		Conn:   cHost,
		Stream: hostDGs,
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
	var ce dbitset.AdaptiveEncoder
	cbs := bitset.MustNew(4)
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// Now the host should send that datagram,
	// and we need to synchronize on that send.
	_ = dtest.ReceiveSoon(t, hostDGs.Ready)
	gotDG := hostDGs.Val
	hostDGs = hostDGs.Next
	require.Equal(t, fx.Cfg.Packets[0], gotDG)

	// Now we are going to send two empty bit sets in a row.
	// This tells the host that we never got the datagram.
	// We shouldn't need a delay in between.
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// Next, the host sends the 1-byte sync message ID and the datagram.
	require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))

	var buf [1]byte
	_, err = io.ReadFull(s, buf[:])
	require.NoError(t, err)
	require.Equal(t, byte(1), buf[0])

	dec := bci.NewPacketDecoder(
		0xAA,
		[]byte("test"),
		7,
		32,
		uint16(len("datagram 0")),
	)
	res, err := dec.Decode(s, bitset.MustNew(4))
	require.NoError(t, err)
	require.Zero(t, res.Packet.ChunkIndex)
	require.Equal(t, fx.Cfg.Packets[0], res.Raw)
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

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, appHeader)

	fx := NewOutgoingRelayFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		3, 1,
	)

	// Mark the first datagram as present,
	// so we can synchronize on sending that out first.
	fx.Cfg.Packets[0] = []byte("\xAAtest\x00\x00datagram 0")
	fx.Cfg.InitialHavePackets.Set(0)

	// The operation is running on the "host" side of the connection.
	cHost, cClient := fx.ListenerSet.Dial(t, 0, 1)
	hostDGs := dpubsub.NewStream[[]byte]()
	cHW := &dquictest.PubsubDatagramSender{
		Conn:   cHost,
		Stream: hostDGs,
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
	var ce dbitset.AdaptiveEncoder
	cbs := bitset.MustNew(4)
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// Now the host should send that datagram,
	// and we need to synchronize on that send.
	_ = dtest.ReceiveSoon(t, hostDGs.Ready)
	gotDG := hostDGs.Val
	hostDGs = hostDGs.Next
	require.Equal(t, fx.Cfg.Packets[0], gotDG)

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
	fx.Cfg.Packets[1] = []byte("\xAAtest\x00\x01datagram 1")
	nad := fx.Cfg.NewAvailablePackets
	nad.Publish(1)
	nad = nad.Next

	// The host forwards the new datagram to the client,
	// and we can synchronize on that.
	_ = dtest.ReceiveSoon(t, hostDGs.Ready)
	gotDG = hostDGs.Val
	hostDGs = hostDGs.Next
	require.NoError(t, err)
	require.Equal(t, fx.Cfg.Packets[1], gotDG)

	// Now the client sends the next delta update, which is still zero.
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// That is two deltas without acknowledging the first datagram.
	require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))

	msgBuf := make([]byte, 1)
	_, err = io.ReadFull(s, msgBuf)
	require.NoError(t, err)
	require.Equal(t, byte(1), msgBuf[0])

	dec := bci.NewPacketDecoder(
		0xAA,
		[]byte("test"),
		7,
		32,
		uint16(len("datagram 0")),
	)
	decHave := bitset.MustNew(4)
	res, err := dec.Decode(s, decHave)
	require.NoError(t, err)
	require.Zero(t, res.Packet.ChunkIndex)
	require.Equal(t, fx.Cfg.Packets[0], res.Raw)
	decHave.Set(0)

	// Do a short read attempt, and it must time out.
	require.NoError(t, s.SetReadDeadline(time.Now().Add(2*time.Millisecond)))

	n, err := io.ReadFull(s, make([]byte, 1))
	require.Error(t, err)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Zero(t, n)

	// And now we send another delta update,
	// this time including the sync datagram index we received.
	cbs.Set(0)
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// That update causes another sync update, finally.
	require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))

	_, err = io.ReadFull(s, msgBuf)
	require.NoError(t, err)
	require.Equal(t, byte(1), msgBuf[0])

	res, err = dec.Decode(s, decHave)
	require.NoError(t, err)
	require.Equal(t, uint16(1), res.Packet.ChunkIndex)
	require.Equal(t, fx.Cfg.Packets[1], res.Raw)

	// Still nothing available to read after that.
	require.NoError(t, s.SetReadDeadline(time.Now().Add(2*time.Millisecond)))
	n, err = io.ReadFull(s, make([]byte, 1))
	require.Error(t, err)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Zero(t, n)
}

func TestOutgoingRelay_dataReady(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const protocolID byte = 0xAA
	broadcastID := []byte("test")
	appHeader := []byte("dummy app header")

	protoHeader := bci.NewProtocolHeader(protocolID, broadcastID, appHeader)

	fx := NewOutgoingRelayFixture(
		t, ctx,
		2,
		protoHeader, appHeader,
		3, 1,
	)

	// Mark the first datagram as present,
	// so we can synchronize on sending that out first.
	fx.Cfg.Packets[0] = []byte("\xAAtest\x00\x00datagram 0")
	fx.Cfg.InitialHavePackets.Set(0)

	// The operation is running on the "host" side of the connection.
	cHost, cClient := fx.ListenerSet.Dial(t, 0, 1)
	hostDGs := dpubsub.NewStream[[]byte]()
	cHW := &dquictest.PubsubDatagramSender{
		Conn:   cHost,
		Stream: hostDGs,
	}
	fx.Run(t, ctx, nil, cHW)

	s, err := cClient.AcceptStream(ctx)
	require.NoError(t, err)

	pid, bid, gotAH, _ := parseHeader(t, s, len(broadcastID))
	require.Equal(t, protocolID, pid)
	require.Equal(t, broadcastID, bid)
	require.Equal(t, appHeader, gotAH)

	// For the client side of the handshake,
	// indicate we have the same single datagram.
	var ce dbitset.AdaptiveEncoder
	cbs := bitset.MustNew(4)
	cbs.Set(0)
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	// Now the host gets all its data somehow.
	fx.Cfg.Packets[1] = []byte("\xAAtest\x00\x01datagram 1")
	fx.Cfg.Packets[2] = []byte("\xAAtest\x00\x02datagram 2")
	fx.Cfg.Packets[3] = []byte("\xAAtest\x00\x03datagram 3")
	close(fx.DataReady)

	// So all three datagrams are sent immediately.
	// But the bitsets are iterated randomly,
	// so we cannot assume their order.
	gotChunkIDs := make([]uint16, 0, 3)
	for range 3 {
		dtest.ReceiveSoon(t, hostDGs.Ready)

		dg := hostDGs.Val
		hostDGs = hostDGs.Next

		if bytes.Equal(dg, fx.Cfg.Packets[1]) {
			gotChunkIDs = append(gotChunkIDs, 1)
		} else if bytes.Equal(dg, fx.Cfg.Packets[2]) {
			gotChunkIDs = append(gotChunkIDs, 2)
		} else if bytes.Equal(dg, fx.Cfg.Packets[3]) {
			gotChunkIDs = append(gotChunkIDs, 3)
		} else {
			t.Fatalf("received unexpected datagram %x", dg)
		}
	}

	require.ElementsMatch(t, []uint16{1, 2, 3}, gotChunkIDs)

	// After the datagrams are sent,
	// the host sends the single byte indicating datagram completion.
	var buf [1]byte
	require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = io.ReadFull(s, buf[:])
	require.NoError(t, err)
	require.Equal(t, byte(0xff), buf[0])

	// The host blocks until we send another bitset update.
	require.NoError(t, ce.SendBitset(s, 50*time.Millisecond, cbs))

	decHave := bitset.MustNew(4)
	decHave.Set(0)
	dec := bci.NewPacketDecoder(
		0xAA,
		[]byte("test"),
		7,
		bcsha256.HashSize,
		uint16(len("datagram 0")),
	)

	res, err := dec.Decode(s, decHave)
	require.NoError(t, err)
	require.False(t, decHave.Test(uint(res.Packet.ChunkIndex)))
	require.Equal(t, fx.Cfg.Packets[res.Packet.ChunkIndex], res.Raw)
	decHave.Set(uint(res.Packet.ChunkIndex))

	// And one more time.
	res, err = dec.Decode(s, decHave)
	require.NoError(t, err)
	require.False(t, decHave.Test(uint(res.Packet.ChunkIndex)))
	require.Equal(t, fx.Cfg.Packets[res.Packet.ChunkIndex], res.Raw)

	// The write-side should be closed now,
	// so the next read should be an EOF.
	n, err := io.ReadFull(s, buf[:])
	require.Zero(t, n)
	require.Error(t, err)
	require.ErrorIs(t, err, io.EOF)
}

func parseHeader(
	t *testing.T,
	s dquic.ReceiveStream,
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

	var sz [2]byte
	_, err = io.ReadFull(s, sz[:])
	require.NoError(t, err)
	gotSize := binary.BigEndian.Uint16(sz[:])

	ah := make([]byte, gotSize)
	_, err = io.ReadFull(s, ah)
	require.NoError(t, err)

	var rat [1]byte
	_, err = io.ReadFull(s, rat[:])
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
		Tracer: dtrace.NopTracerProvider().Tracer("NewOutgoingRelayFixture"),

		WG: new(sync.WaitGroup),

		// Conn injected in Run call.

		ProtocolHeader: protocolHeader,
		AppHeader:      appHeader,

		Packets: make([][]byte, nData+nParity),

		InitialHavePackets: bitset.MustNew(uint(nData + nParity)),

		NewAvailablePackets: dpubsub.NewStream[uint](),

		DataReady: dataReady,

		NData:   nData,
		NParity: nParity,

		Timing: bci.DefaultOriginationTiming(),
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
	conn dquic.Conn,
) {
	t.Helper()

	// Ensure that all provided packets have the correct prefix.
	// If not, the tests can end up behaving differently from how production code works.
	protoID := f.Cfg.ProtocolHeader.ProtocolID()
	bID := f.Cfg.ProtocolHeader.BroadcastID()
	for u, ok := f.Cfg.InitialHavePackets.NextSet(0); ok; u, ok = f.Cfg.InitialHavePackets.NextSet(u + 1) {
		p := f.Cfg.Packets[u]
		require.Equal(t, protoID, p[0], "packet did not start with protocol ID")
		require.Equal(t, bID, p[1:1+len(bID)], "packet had protocol ID but not broadcast ID")

		chunkID := binary.BigEndian.Uint16(p[1+len(bID) : 1+len(bID)+2])
		require.Equal(t, u, uint(chunkID), "packet had protocol and broadcast ID but missing/wrong chunk ID")
	}

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
	dquic.Conn

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
