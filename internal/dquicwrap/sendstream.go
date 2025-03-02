package dquicwrap

import (
	"context"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"
)

// sendStream wraps a real quic.SendStream.
//
// It can be unexported here because the type
// is not exposed directly outside of this package.
//
// Normally one might embed the wrapped interface value,
// but in this case we want to be extremely precise
// about the behavior of every method.
type sendStream struct {
	q quic.SendStream

	// Track whether this is the first write.
	// We require that the very first byte is >= 128,
	// so that the application layer streams
	// can be handled separately from the protocol layer streams.
	writtenBefore bool
}

var _ quic.SendStream = (*sendStream)(nil)

// StreamID implements [quic.ReceiveStream] and [quic.SendStream].
func (s *sendStream) StreamID() quic.StreamID {
	// Direct call.
	return s.q.StreamID()
}

// Write implements [quic.SendStream].
func (s *sendStream) Write(p []byte) (int, error) {
	if !s.writtenBefore && len(p) > 0 {
		if p[0] < 128 {
			panic(fmt.Errorf(
				"BUG: first byte written to application stream must be >= 128 (got %d)",
				p[0],
			))
		}

		s.writtenBefore = true
	}

	return s.q.Write(p)
}

// Close implements [quic.SendStream].
func (s *sendStream) Close() error {
	// Direct call.
	return s.q.Close()
}

// CancelWrite implements [quic.SendStream].
func (s *sendStream) CancelWrite(code quic.StreamErrorCode) {
	// Direct call.
	s.q.CancelWrite(code)
}

// Context implements [quic.SendStream].
func (s *sendStream) Context() context.Context {
	return s.q.Context()
}

// SetWriteDeadline implements [quic.SendStream].
func (s *sendStream) SetWriteDeadline(t time.Time) error {
	return s.q.SetWriteDeadline(t)
}
