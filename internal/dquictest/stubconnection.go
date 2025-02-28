package dquictest

import (
	"context"
	"net"

	"github.com/quic-go/quic-go"
)

type StubConnection struct {
	// The value to return from the Context method.
	// If nil, the method returns [context.Background()].
	ContextValue context.Context

	// The value to return from the ConnectionState method.
	ConnectionStateValue quic.ConnectionState

	LocalAddrValue, RemoteAddrValue StubNetAddr
}

var _ quic.Connection = (*StubConnection)(nil)

// AcceptStream implements [quic.Connection].
func (c *StubConnection) AcceptStream(ctx context.Context) (quic.Stream, error) {
	// TODO: add a way to inject a stream for acceptance.
	<-ctx.Done()
	return nil, ctx.Err()
}

// AcceptUniStream implements [quic.Connection].
func (c *StubConnection) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	panic("stub does not support AcceptUniStream")
}

// OpenStream implements [quic.Connection].
func (c *StubConnection) OpenStream() (quic.Stream, error) {
	panic("stub does not support OpenStream")
}

// OpenStreamSync implements [quic.Connection].
func (c *StubConnection) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	panic("stub does not support OpenStreamSync")
}

// OpenUniStream implements [quic.Connection].
func (c *StubConnection) OpenUniStream() (quic.SendStream, error) {
	panic("stub does not support OpenUniStream")
}

// OpenUniStreamSync implements [quic.Connection].
func (c *StubConnection) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	panic("stub does not support OpenUniStreamSync")
}

// LocalAddr implements [quic.Connection].
func (c *StubConnection) LocalAddr() net.Addr {
	return c.LocalAddrValue
}

// RemoteAddr implements [quic.Connection].
func (c *StubConnection) RemoteAddr() net.Addr {
	return c.RemoteAddrValue
}

// CloseWithError implements [quic.Connection].
func (c *StubConnection) CloseWithError(
	code quic.ApplicationErrorCode, msg string,
) error {
	return nil
}

// Context implements [quic.Connection].
func (c *StubConnection) Context() context.Context {
	if c.ContextValue == nil {
		return context.Background()
	}
	return c.ContextValue
}

// ConnectionState implements [quic.Connection].
func (c *StubConnection) ConnectionState() quic.ConnectionState {
	return c.ConnectionStateValue
}

// SendDatagram implements [quic.Connection].
func (c *StubConnection) SendDatagram(p []byte) error {
	panic("stub does not support SendDatagram")
}

// ReceiveDatagram implements [quic.Connection].
func (c *StubConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	panic("stub does not support ReceiveDatagram")
}

type StubNetAddr struct {
	NetworkValue string
	StringValue  string
}

var _ net.Addr = StubNetAddr{}

func (a StubNetAddr) Network() string { return a.NetworkValue }
func (a StubNetAddr) String() string  { return a.StringValue }
