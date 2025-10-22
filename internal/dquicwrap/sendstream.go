package dquicwrap

import (
	"fmt"
	"time"

	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dquic"
)

// sendStream wraps a dquic.SendStream,
// ensuring the first written byte exceeds [dconn.MinAppProtocolID].
//
// It can be unexported here because the type
// is not exposed directly outside of this package.
//
// Normally one might embed the wrapped interface value,
// but in this case we want to be extremely precise
// about the behavior of every method.
type sendStream struct {
	dq dquic.SendStream

	// Track whether this is the first write.
	// We require that the very first byte is >= [dconn.MinAppProtocolID],
	// so that the application layer streams
	// can be handled separately from the protocol layer streams.
	writtenBefore bool
}

var _ dquic.SendStream = (*sendStream)(nil)

// Write implements [quic.SendStream].
func (s *sendStream) Write(p []byte) (int, error) {
	if !s.writtenBefore && len(p) > 0 {
		if p[0] < dconn.MinAppProtocolID {
			panic(fmt.Errorf(
				"BUG: first byte written to application stream must be >= %d (got %d)",
				dconn.MinAppProtocolID, p[0],
			))
		}

		s.writtenBefore = true
	}

	return s.dq.Write(p)
}

// Close implements [quic.SendStream].
func (s *sendStream) Close() error {
	// Direct call.
	return s.dq.Close()
}

// CancelWrite implements [quic.SendStream].
func (s *sendStream) CancelWrite(code dquic.StreamErrorCode) {
	// Direct call.
	s.dq.CancelWrite(code)
}

// SetWriteDeadline implements [quic.SendStream].
func (s *sendStream) SetWriteDeadline(t time.Time) error {
	return s.dq.SetWriteDeadline(t)
}
