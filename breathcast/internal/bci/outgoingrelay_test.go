package bci_test

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/breathcast/internal/bci"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
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

	datagrams := make([][]byte, 4)

	// Kind of a fake datagram.
	// It must have the protocol ID and broadcast ID first,
	// and everything that follows is treated opaquely,
	// at least until HandleDatagram is called.
	datagrams[0] = []byte("\xAAtestdatagram 0")
	initialHave := bitset.MustNew(4)
	initialHave.Set(0)

	ls := dquictest.NewListenerSet(t, ctx, 2)
	cHost, cClient := ls.Dial(t, 0, 1)

	bci.RunOutgoingRelay(ctx, dtest.NewLogger(t), bci.OutgoingRelayConfig{
		WG: &wg,

		Conn: cHost,

		ProtocolHeader: protoHeader,

		AppHeader: appHeader,

		Datagrams: datagrams,

		InitialHaveDatagrams: initialHave,

		NewAvailableDatagrams: dchan.NewMulticast[uint](),

		// DataReady omitted.

		NData:   3,
		NParity: 1,
	})

	s, err := cClient.AcceptStream(ctx)
	require.NoError(t, err)

	// First confirm the header looks correct.
	var pid [1]byte
	_, err = io.ReadFull(s, pid[:])
	require.NoError(t, err)
	require.Equal(t, protocolID, pid[0])

	var bid [4]byte
	_, err = io.ReadFull(s, bid[:])
	require.NoError(t, err)
	require.Equal(t, broadcastID, bid[:])

	// Ignore the ratio byte for now.
	// That needs some different handling.
	// Reuse the 1-byte array.
	_, err = io.ReadFull(s, pid[:])
	require.NoError(t, err)

	// Length of app header.
	var sz [2]byte
	_, err = io.ReadFull(s, sz[:])
	require.NoError(t, err)
	gotSize := binary.BigEndian.Uint16(sz[:])
	require.Equal(t, uint16(len(appHeader)), gotSize)

	receivedAppHeader := make([]byte, gotSize)
	_, err = io.ReadFull(s, receivedAppHeader)
	require.NoError(t, err)
	require.Equal(t, appHeader, receivedAppHeader)

	// For the client side of the handshake,
	// just send 4 zero bytes to indicate that we have no datagrams.
	require.NoError(t, s.SetWriteDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = s.Write(make([]byte, 4))
	require.NoError(t, err)

	dgCtx, dgCancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer dgCancel()
	dg, err := cClient.ReceiveDatagram(dgCtx)
	require.NoError(t, err)
	require.Equal(t, datagrams[0], dg)
}
