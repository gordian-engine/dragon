package dquicwrap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/gordian-engine/dragon/dquic"
)

// Conn wraps a [dquic.Conn], for the dpeerset package.
//
// Normally one might embed the wrapped interface value,
// but in this case we want to be extremely precise
// about the behavior of every method.
type Conn struct {
	dq dquic.Conn

	streams <-chan *Stream
}

// NewConn returns a Conn wrapping the given plain dquic.Conn.
//
// The incomingStreams channel determines the streams that reach AcceptStream.
// There should be another goroutine that accepts the raw streams,
// and then parses the first byte in order to determine
// whether the stream should be routed to the "application layer" (here)
// or remain in the protocol layer.
// (In practice, the [*dpeerset.peerInboundProcessor] does this work.)
func NewConn(q dquic.Conn, incomingStreams <-chan *Stream) *Conn {
	return &Conn{
		dq:      q,
		streams: incomingStreams,
	}
}

// WrapsConnection reports whether c is wrapping conn.
// This is only intended for tests.
func (c *Conn) WrapsConnection(conn dquic.Conn) bool {
	return c.dq == conn
}

var _ dquic.Conn = (*Conn)(nil)

func (c *Conn) Context() context.Context {
	return c.dq.Context()
}

// AcceptStream implements [dquic.Conn].
func (c *Conn) AcceptStream(ctx context.Context) (dquic.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"context canceled while waiting to accept stream: %w",
			context.Cause(ctx),
		)
	case s := <-c.streams:
		return s, nil
	}
}

// AcceptUniStream implements [dquic.Conn].
func (c *Conn) AcceptUniStream(ctx context.Context) (dquic.ReceiveStream, error) {
	// Direct call here because we don't do anything with uni streams
	// at the protocol layer, currently.
	// And we don't need to wrap receive streams, either.
	return c.dq.AcceptUniStream(ctx)
}

// OpenStreamSync implements [dquic.Conn].
func (c *Conn) OpenStreamSync(ctx context.Context) (dquic.Stream, error) {
	s, err := c.dq.OpenStreamSync(ctx)
	if err != nil {
		// Don't want to wrap the underlying error in this case.
		return nil, err
	}

	return NewOutboundStream(s), nil
}

// OpenUniStreamSync implements [dquic.Conn].
func (c *Conn) OpenUniStreamSync(ctx context.Context) (dquic.SendStream, error) {
	s, err := c.dq.OpenUniStreamSync(ctx)
	if err != nil {
		// Don't want to wrap the underlying error in this case.
		return nil, err
	}

	return &sendStream{dq: s}, nil
}

// LocalAddr implements [dquic.Conn].
func (c *Conn) LocalAddr() net.Addr { return c.dq.LocalAddr() }

// RemoteAddr implements [dquic.Conn].
func (c *Conn) RemoteAddr() net.Addr { return c.dq.RemoteAddr() }

// CloseWithError implements [dquic.Conn].
func (c *Conn) CloseWithError(
	code dquic.ApplicationErrorCode, msg string,
) error {
	return c.dq.CloseWithError(code, msg)
}

// TLSConnectionState implements [dquic.Conn].
func (c *Conn) TLSConnectionState() tls.ConnectionState {
	return c.dq.TLSConnectionState()
}

// SendDatagram implements [dquic.Conn].
func (c *Conn) SendDatagram(p []byte) error {
	return c.dq.SendDatagram(p)
}

// ReceiveDatagram implements [dquic.Conn].
func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.dq.ReceiveDatagram(ctx)
}
