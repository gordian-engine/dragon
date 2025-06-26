package dpubsub_test

import (
	"context"
	"testing"

	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestStream_Publish_panicsOnCalledTwice(t *testing.T) {
	t.Parallel()

	s := dpubsub.NewStream[int]()
	s.Publish(1)

	require.Panics(t, func() {
		s.Publish(1)
	})
}

func TestRunChannelToStream_stopsOnContextDone(t *testing.T) {
	t.Parallel()

	// Unbuffered so we know sends are received.
	ch := make(chan int)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, done := dpubsub.RunChannelToStream(ctx, ch)

	dtest.SendSoon(t, ch, 1)
	dtest.SendSoon(t, ch, 2)
	cancel()

	dtest.ReceiveSoon(t, done)

	dtest.IsSending(t, s.Ready)
	require.Equal(t, s.Val, 1)

	s = s.Next

	dtest.IsSending(t, s.Ready)
	require.Equal(t, s.Val, 2)

	s = s.Next
	dtest.NotSending(t, s.Ready)
}

func TestRunChannelToStream_stopsOnChannelClosed(t *testing.T) {
	t.Parallel()

	// Unbuffered so we know sends are received.
	ch := make(chan int)

	s, done := dpubsub.RunChannelToStream(context.Background(), ch)

	dtest.SendSoon(t, ch, 1)
	dtest.SendSoon(t, ch, 2)
	close(ch)

	dtest.ReceiveSoon(t, done)

	dtest.IsSending(t, s.Ready)
	require.Equal(t, s.Val, 1)

	s = s.Next

	dtest.IsSending(t, s.Ready)
	require.Equal(t, s.Val, 2)

	s = s.Next
	dtest.NotSending(t, s.Ready)
}
