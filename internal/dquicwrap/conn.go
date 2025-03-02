package dquicwrap

import (
	"context"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
)

// Conn wraps a real quic.Connection.
//
// Normally one might embed the wrapped interface value,
// but in this case we want to be extremely precise
// about the behavior of every method.
type Conn struct {
	q quic.Connection

	streams <-chan *Stream
}

func NewConn(q quic.Connection, incomingStreams <-chan *Stream) *Conn {
	return &Conn{
		q:       q,
		streams: incomingStreams,
	}
}

// WrapsConnection reports whether c is wrapping conn.
// This is only intended for tests.
func (c *Conn) WrapsConnection(conn quic.Connection) bool {
	return c.q == conn
}

var _ quic.Connection = (*Conn)(nil)

// AcceptStream implements [quic.Connection].
func (c *Conn) AcceptStream(ctx context.Context) (quic.Stream, error) {
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

// AcceptUniStream implements [quic.Connection].
func (c *Conn) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	// Direct call here because we don't do anything with uni streams
	// at the protocol layer, currently.
	// And we don't need to wrap receive streams, either.
	return c.q.AcceptUniStream(ctx)
}

// OpenStream implements [quic.Connection].
func (c *Conn) OpenStream() (quic.Stream, error) {
	s, err := c.q.OpenStream()
	if err != nil {
		// Don't want to wrap the underlying error in this case.
		return nil, err
	}

	return NewStream(s, 0), nil
}

// OpenStreamSync implements [quic.Connection].
func (c *Conn) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	s, err := c.q.OpenStreamSync(ctx)
	if err != nil {
		// Don't want to wrap the underlying error in this case.
		return nil, err
	}

	return NewStream(s, 0), nil
}

// OpenUniStream implements [quic.Connection].
func (c *Conn) OpenUniStream() (quic.SendStream, error) {
	s, err := c.q.OpenUniStream()
	if err != nil {
		// Don't want to wrap the underlying error in this case.
		return nil, err
	}

	return &sendStream{q: s}, nil
}

// OpenUniStreamSync implements [quic.Connection].
func (c *Conn) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	s, err := c.q.OpenUniStreamSync(ctx)
	if err != nil {
		// Don't want to wrap the underlying error in this case.
		return nil, err
	}

	return &sendStream{q: s}, nil
}

// LocalAddr implements [quic.Connection].
func (c *Conn) LocalAddr() net.Addr { return c.q.LocalAddr() }

// RemoteAddr implements [quic.Connection].
func (c *Conn) RemoteAddr() net.Addr { return c.q.RemoteAddr() }

// CloseWithError implements [quic.Connection].
func (c *Conn) CloseWithError(
	code quic.ApplicationErrorCode, msg string,
) error {
	return c.q.CloseWithError(code, msg)
}

// Context implements [quic.Connection].
func (c *Conn) Context() context.Context { return c.q.Context() }

// ConnectionState implements [quic.Connection].
func (c *Conn) ConnectionState() quic.ConnectionState {
	return c.q.ConnectionState()
}

// SendDatagram implements [quic.Connection].
func (c *Conn) SendDatagram(p []byte) error {
	return c.q.SendDatagram(p)
}

// ReceiveDatagram implements [quic.Connection].
func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.q.ReceiveDatagram(ctx)
}
