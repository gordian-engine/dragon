package dquic_test

import (
	"context"
	"io"
	"testing"

	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestDial_stream(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ls := dquictest.NewListenerSet(t, ctx, 2)

	connAcceptedCh := make(chan quic.Connection, 1)
	go func() {
		acceptedConn, err := ls.QLs[1].Accept(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		connAcceptedCh <- acceptedConn
	}()
	res, err := ls.Dialer(0).Dial(ctx, ls.UDPConns[1].LocalAddr())
	require.NoError(t, err)

	acceptedConn := dtest.ReceiveSoon(t, connAcceptedCh)
	require.NotNil(t, acceptedConn)

	createdConn := res.Conn

	streamAcceptedCh := make(chan quic.Stream, 1)
	go func() {
		acceptedStream, err := acceptedConn.AcceptStream(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		streamAcceptedCh <- acceptedStream
	}()

	createdStream, err := createdConn.OpenStream()
	require.NoError(t, err)
	_, err = io.WriteString(createdStream, "hello")
	require.NoError(t, err)

	acceptedStream := dtest.ReceiveSoon(t, streamAcceptedCh)

	buf := make([]byte, 5)
	_, err = io.ReadFull(acceptedStream, buf)
	require.NoError(t, err)

	require.Equal(t, "hello", string(buf))
}
