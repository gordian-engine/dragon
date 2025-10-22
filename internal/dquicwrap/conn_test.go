package dquicwrap_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dquicwrap"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestConn_outgoingStream_firstByteMustBeAppProtocol(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ls := dquictest.NewListenerSet(t, ctx, 2)
	c0, _ := ls.Dial(t, 0, 1)

	w0 := dquicwrap.NewConn(c0, nil)
	s, err := w0.OpenStreamSync(ctx)
	require.NoError(t, err)

	require.Panics(t, func() {
		_, _ = s.Write([]byte{1})
	})
}

func TestConn_outgoingStream_firstByteSucceedsAsAppProtocol(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ls := dquictest.NewListenerSet(t, ctx, 2)
	c0, c1 := ls.Dial(t, 0, 1)

	w0 := dquicwrap.NewConn(c0, nil)
	s, err := w0.OpenStreamSync(ctx)
	require.NoError(t, err)

	_, err = s.Write([]byte{dconn.MinAppProtocolID})
	require.NoError(t, err)

	// Raw receiving connection sees the app protocol byte.
	s, err = c1.AcceptStream(ctx)
	require.NoError(t, err)

	require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))

	var buf [1]byte
	_, err = io.ReadFull(s, buf[:])
	require.NoError(t, err)

	require.Equal(t, dconn.MinAppProtocolID, buf[0])
}

func TestConn_firstByteResponse_allowedToBeBelowMinAppProtocol(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ls := dquictest.NewListenerSet(t, ctx, 2)
	c0, c1 := ls.Dial(t, 0, 1)

	incomingStreams := make(chan *dquicwrap.Stream, 1)
	w0 := dquicwrap.NewConn(c0, incomingStreams)

	// Now the raw connection c1 opens a stream to c0.
	rawS10, err := c1.OpenStreamSync(ctx)
	require.NoError(t, err)

	// It writes an application-protocol byte.
	_, err = rawS10.Write([]byte{0xf0})
	require.NoError(t, err)

	// Dragon internals "intercept" this stream.
	rawS01, err := c0.AcceptStream(ctx)
	require.NoError(t, err)

	var buf [1]byte
	_, err = io.ReadFull(rawS01, buf[:])
	require.NoError(t, err)
	require.Equal(t, byte(0xf0), buf[0])

	interceptedS01 := dquicwrap.NewInboundStream(rawS01, buf[0])
	dtest.SendSoon(t, incomingStreams, interceptedS01)

	// Now the wrapped connection can accept the stream.
	wrappedS01, err := w0.AcceptStream(ctx)
	require.NoError(t, err)

	// That first byte is read successfully.
	require.NoError(t, wrappedS01.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = io.ReadFull(wrappedS01, buf[:])
	require.NoError(t, err)
	require.Equal(t, byte(0xf0), buf[0])

	// And now, the wrapped stream can respond with a byte
	// that isn't in the application protocol range.

	_, err = wrappedS01.Write([]byte{4})
	require.NoError(t, err)

	// Then that initial raw stream can read the byte successfully.
	require.NoError(t, rawS10.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = io.ReadFull(rawS10, buf[:])
	require.NoError(t, err)
	require.Equal(t, byte(4), buf[0])
}
