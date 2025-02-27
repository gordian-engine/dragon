package dqw

import (
	"time"

	"github.com/quic-go/quic-go"
)

// stream wraps a real quic.Stream.
//
// It can be unexported here because the type
// is not exposed directly outside of this package.
//
// Normally one might embed the wrapped interface value,
// but in this case we want to be extremely precise
// about the behavior of every method.
type stream struct {
	// Just embed the receive stream,
	// because we don't do any intercepting on receive streams.
	quic.ReceiveStream

	// Also embed the wrapped send stream,
	sendStream

	// Still need a reference q directly for SetDeadline.
	q quic.Stream
}

func newStream(q quic.Stream) *stream {
	return &stream{
		ReceiveStream: q,
		sendStream: sendStream{
			q: q,
		},
	}
}

var _ quic.Stream = (*stream)(nil)

// SetDeadline implements [quic.Stream].
func (s *stream) SetDeadline(t time.Time) error {
	// Direct call.
	return s.q.SetDeadline(t)
}

// StreamID implements [quic.ReceiveStream] and [quic.SendStream].
// (We need to declare it here due to embedding ambiguity).
func (s *stream) StreamID() quic.StreamID {
	// Direct call.
	return s.q.StreamID()
}
