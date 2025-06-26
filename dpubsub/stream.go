package dpubsub

import "context"

// Stream is a linked list of event-driven values.
// The list has a single writer and many readers.
// Readers can each consume the list at their own pace.
//
// If readers do not actively consume the list,
// the node they observe will never be garbage collected,
// which is a memory leak.
type Stream[T any] struct {
	Ready chan struct{}
	Next  *Stream[T]
	Val   T
}

// NewStream returns an initialized pubsub stream.
func NewStream[T any]() *Stream[T] {
	return &Stream[T]{
		Ready: make(chan struct{}),
	}
}

// Publish assigns s's value and initializes s.Next.
// Then s.Ready is closed, notifying any observers that
// s.Val can now be safely read.
//
// If Publish is called twice for the same s, Publish panics.
func (s *Stream[T]) Publish(t T) {
	s.Val = t
	s.Next = NewStream[T]()
	close(s.Ready)
}

// RunChannelToStream starts a background goroutine
// that reads values from ch and publishes them to the returned Stream.
//
// The returned done channel is closed when the goroutine stops,
// which will happen on context cancellation or
// if the given channel is closed.
func RunChannelToStream[T any](ctx context.Context, ch <-chan T) (
	s *Stream[T], done <-chan struct{},
) {
	s = NewStream[T]()
	doneCh := make(chan struct{})

	go runChannelToStream(ctx, ch, s, doneCh)

	return s, doneCh
}

func runChannelToStream[T any](
	ctx context.Context,
	ch <-chan T,
	s *Stream[T],
	done chan<- struct{},
) {
	defer close(done)

	for {
		select {
		case <-ctx.Done():
			return

		case v, ok := <-ch:
			if !ok {
				return
			}
			s.Publish(v)
			s = s.Next
		}
	}
}
