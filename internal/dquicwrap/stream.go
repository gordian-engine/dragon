package dquicwrap

import (
	"time"

	"github.com/gordian-engine/dragon/dconn"
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

	// Also embed the wrapped send stream.
	sendStream

	// Still need a reference to q directly for SetDeadline.
	q quic.Stream

	// Only accessed from Read,
	// which presumably is not going to be called concurrently.
	hasRead bool

	prependProtocolID byte
}

// NewOutboundStream returns a wrapped stream
// that requires that the first outbound byte
// is >= [dconn.MinAppProtocolID].
func NewOutboundStream(q quic.Stream) *Stream {
	return &Stream{
		ReceiveStream: q,
		sendStream: sendStream{
			q: q,
		},

		// Since this is an outbound stream,
		// set hasRead true to avoid any special behavior in Read.
		hasRead: true,
	}
}

// NewInboundStream returns a wrapped stream
// that prepends the first read with the given
// alreadyConsumedProtocolID byte.
//
// This is used when dragon internals intercept an incoming stream
// and then inspect the first byte,
// to decide whether the stream should be routed
// to the application layer or remain in the p2p protocol layer.
func NewInboundStream(
	q quic.Stream,
	alreadyConsumedProtocolID byte,
) *Stream {
	return &Stream{
		ReceiveStream: q,

		sendStream: sendStream{
			q: q,

			// Set this true to avoid a protocol byte check.
			// Since it's an inbound stream,
			// our first write will be a reply
			// and we can write whatever first byte we'd like.
			writtenBefore: true,
		},

		prependProtocolID: alreadyConsumedProtocolID,
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
	if !s.hasRead && len(p) > 0 && s.prependProtocolID >= dconn.MinAppProtocolID {
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
