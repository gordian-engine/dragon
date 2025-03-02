package dquicwrap

import (
	"time"

	"github.com/quic-go/quic-go"
)

// Stream wraps a real quic.Stream.
//
// Normally one might embed the wrapped interface value,
// but in this case we want to be extremely precise
// about the behavior of every method.
type Stream struct {
	// Just embed the receive stream,
	// because we don't do any intercepting on receive streams.
	quic.ReceiveStream

	// Also embed the wrapped send stream,
	sendStream

	// Still need a reference q directly for SetDeadline.
	q quic.Stream

	// Only accessed from Read,
	// which presumably is not going to be called concurrently.
	hasRead bool

	prependProtocolID byte
}

// NewStream returns a new Stream based on the given quic.Stream.
// If protocolID is >= 128, that byte value
// will be prepended to the first read;
// this is an implementation detail in the way dynamic streams are handled.
func NewStream(q quic.Stream, protocolID byte) *Stream {
	return &Stream{
		ReceiveStream: q,
		sendStream: sendStream{
			q: q,
		},

		prependProtocolID: protocolID,
	}
}

var _ quic.Stream = (*Stream)(nil)

// SetDeadline implements [quic.Stream].
func (s *Stream) SetDeadline(t time.Time) error {
	// Direct call.
	return s.q.SetDeadline(t)
}

// StreamID implements [quic.ReceiveStream] and [quic.SendStream].
// (We need to declare it here due to embedding ambiguity).
func (s *Stream) StreamID() quic.StreamID {
	// Direct call.
	return s.q.StreamID()
}

// TODO: we need to extract a ReceiveStream
// and move this declaration to that type.
func (s *Stream) Read(p []byte) (int, error) {
	didPrepend := false
	if !s.hasRead && len(p) > 0 && s.prependProtocolID >= 128 {
		// TODO: 128 should be a constant somewhere.

		p[0] = s.prependProtocolID
		s.hasRead = true
		p = p[1:]

		didPrepend = true
	}

	n, err := s.ReceiveStream.Read(p)
	if didPrepend {
		n++
	}
	return n, err
}
