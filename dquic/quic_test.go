package dquic_test

import (
	"context"
	"io"
	"testing"

	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestDial_stream(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ls := dquictest.NewListenerSet(t, ctx, 2)

	acceptedConn, createdConn := ls.Dial(t, 0, 1)

	streamAcceptedCh := make(chan dquic.Stream, 1)
	go func() {
		acceptedStream, err := acceptedConn.AcceptStream(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		streamAcceptedCh <- acceptedStream
	}()

	createdStream, err := createdConn.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = io.WriteString(createdStream, "hello")
	require.NoError(t, err)

	acceptedStream := dtest.ReceiveSoon(t, streamAcceptedCh)

	buf := make([]byte, 5)
	_, err = io.ReadFull(acceptedStream, buf)
	require.NoError(t, err)

	require.Equal(t, "hello", string(buf))
}
