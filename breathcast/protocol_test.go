package breathcast_test

import (
	"context"
	"crypto/sha256"
	"io"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestProtocol_Originate_header(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := dtest.NewLogger(t)
	connChanges := make(chan dconn.Change)
	p := breathcast.NewProtocol(ctx, log, breathcast.ProtocolConfig{
		ConnectionChanges: connChanges,

		ProtocolID: 0x91,
	})

	defer p.Wait()
	defer cancel()

	ls := dquictest.NewListenerSet(t, ctx, 2)

	createdConn, acceptedConn := ls.Dial(t, 0, 1)

	dtest.SendSoon(t, connChanges, dconn.Change{
		Conn: dconn.Conn{
			QUIC:  createdConn,
			Chain: ls.Leaves[1].Chain,
		},
		Adding: true,
	})

	// Now the application chooses to Originate.
	header := []byte("dummy header")

	dataChunks := [][]byte{
		[]byte("data0"),
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
	}

	parityChunks := [][]byte{
		[]byte("parity0"),
	}

	// Get ready to accept the stream before the call to originate.
	acceptedStreamCh := make(chan quic.Stream, 1)
	go func() {
		acceptedStream, err := acceptedConn.AcceptStream(ctx)
		if err != nil {
			t.Error(err)
			acceptedStreamCh <- nil
			return
		}
		acceptedStreamCh <- acceptedStream
	}()

	_, err := p.Originate(ctx, header, dataChunks, parityChunks)
	require.NoError(t, err)

	acceptedStream := dtest.ReceiveSoon(t, acceptedStreamCh)
	require.NotNil(t, acceptedStream)

	headerBuf := make([]byte, 1)
	_, err = io.ReadFull(acceptedStream, headerBuf)
	require.NoError(t, err)
	require.Equal(t, []byte{0x91}, headerBuf)

	// Caller must manually set the read deadline before extracting broadcast header.
	require.NoError(t, acceptedStream.SetReadDeadline(time.Now().Add(time.Second)))
	extractedHeader, err := breathcast.ExtractStreamBroadcastHeader(acceptedStream, nil)
	require.NoError(t, err)

	require.Equal(t, header, extractedHeader)

	// At this point the receiver has the raw application header from origination.
	// Feedback to the originator is covered in other tests.
	// This test is kept simpler and shorter with only one side of the protocol,
	// for the sake of an easier-to-debug test if things break during development.
}

func TestProtocolOriginate_accept(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := dtest.NewLogger(t)
	connChanges := make(chan dconn.Change)
	pc := breathcast.ProtocolConfig{
		ConnectionChanges: connChanges,

		ProtocolID: 0x91,

		BroadcastIDLength: 3,
	}
	po := breathcast.NewProtocol(ctx, log.With("side", "originator"), pc)
	pa := breathcast.NewProtocol(ctx, log.With("side", "acceptor"), pc)

	defer po.Wait()
	defer pa.Wait()
	defer cancel()

	ls := dquictest.NewListenerSet(t, ctx, 2)

	createdConn, acceptedConn := ls.Dial(t, 0, 1)

	dtest.SendSoon(t, connChanges, dconn.Change{
		Conn: dconn.Conn{
			QUIC:  createdConn,
			Chain: ls.Leaves[1].Chain,
		},
		Adding: true,
	})

	// Now the application chooses to Originate.
	appHeader := []byte("dummy header")

	dataChunks := [][]byte{
		[]byte("data0"),
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
	}

	parityChunks := [][]byte{
		[]byte("prty0"),
	}

	// Get ready to accept the stream before the call to originate.
	acceptedStreamCh := make(chan quic.Stream, 1)
	go func() {
		acceptedStream, err := acceptedConn.AcceptStream(ctx)
		if err != nil {
			t.Error(err)
			acceptedStreamCh <- nil
			return
		}
		acceptedStreamCh <- acceptedStream
	}()

	_, err := po.Originate(ctx, appHeader, dataChunks, parityChunks)
	require.NoError(t, err)

	acceptedStream := dtest.ReceiveSoon(t, acceptedStreamCh)
	require.NotNil(t, acceptedStream)

	headerBuf := make([]byte, 1)
	_, err = io.ReadFull(acceptedStream, headerBuf)
	require.NoError(t, err)
	require.Equal(t, []byte{0x91}, headerBuf)

	// Caller must manually set the read deadline before extracting broadcast header.
	require.NoError(t, acceptedStream.SetReadDeadline(time.Now().Add(time.Second)))
	extractedHeader, err := breathcast.ExtractStreamBroadcastHeader(acceptedStream, nil)
	require.NoError(t, err)

	require.Equal(t, appHeader, extractedHeader)

	// Now the acceptor accepts the operation.
	// Normally there would be real application logic
	// to translate the received app header into an accepted broadcast config.

	// The fake root proof needs to be the correct length,
	// so just sha256 some text.
	fakeRootProof := sha256.Sum256([]byte("fake root proof"))

	// The acceptor is also responsible for mapping relay tasks with streams.
	// Since this would be the first stream for this operation,
	// we create a new relay task out of band.
	ro, err := pa.CreateRelayOperation(
		// Normally there would be a separately canceled context,
		// but we don't care about that for this test,
		// since the root context is canceled at the end.
		ctx, ctx,
		breathcast.RelayOperationConfig{
			BroadcastID: []byte("op1"),

			// We didn't use PrepareOrigination,
			// so we don't have a real root proof here.
			RootProof: [][]byte{
				fakeRootProof[:],
			},

			NData:   uint16(len(dataChunks)),
			NParity: uint16(len(parityChunks)),

			ShardSize: 5,

			AckTimeout: 50 * time.Millisecond,
		},
	)
	require.NoError(t, err)

	require.NoError(t, ro.AcceptBroadcast(ctx, acceptedStream))

	// Now the originator should send all chunks as datagrams.
	// We are ignoring them for this test.
	// And after sending the datagrams,
	// the originator sends another 0xFF byte to indicate that
	// unreliable sends have completed.
	require.NoError(t, acceptedStream.SetReadDeadline(time.Now().Add(time.Second)))

	completionBuf := make([]byte, 1)
	_, err = io.ReadFull(acceptedStream, completionBuf)
	require.NoError(t, err)
	require.Equal(t, []byte{0xFF}, completionBuf)

	// TODO: indicate that we have nothing and confirm that data chunks are sent.
}
