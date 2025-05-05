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
		Continue:   make(chan struct{}),
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
	dtest.SendSoon(t, cWH.Continue, struct{}{})

	// Now we indicate that the next datagram is available to the host.
	// It would have arrived from a separate peer somehow.
	ad := fx.Cfg.NewAvailableDatagrams
	ad.Set(1)
	ad = ad.Next

	// Then if we are able to send another continue signal,
	// the host tried to send the datagram.
	dtest.SendSoon(t, cWH.Continue, struct{}{})

	require.Equal(t, [][]byte{
		fx.Cfg.Datagrams[0],
		fx.Cfg.Datagrams[1],
	}, cWH.Sent)
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
	bci.RunOutgoingRelay(ctx, log, f.Cfg)
}

type blockingSendDatagram struct {
	quic.Connection

	Ctx      context.Context
	Continue chan struct{}

	Sent [][]byte
}

func (b *blockingSendDatagram) SendDatagram(d []byte) error {
	select {
	case <-b.Ctx.Done():
		return b.Ctx.Err()
	case <-b.Continue:
		// Okay.
	}

	b.Sent = append(b.Sent, d)
	return nil
}
