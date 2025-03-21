package breathcast_test

import (
	"context"
	"io"
	"testing"

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

	headerBuf := make([]byte, 1+len(header))
	_, err = io.ReadFull(acceptedStream, headerBuf)
	require.NoError(t, err)

	require.Equal(t, "\x91"+string(header), string(headerBuf))
}
