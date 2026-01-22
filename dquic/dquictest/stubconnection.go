package dquictest

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/gordian-engine/dragon/dquic"
)

type StubConnection struct {
	// The value to return from the TLSConnectionState method.
	TLSConnectionStateValue tls.ConnectionState

	LocalAddrValue, RemoteAddrValue StubNetAddr
}

var _ dquic.Conn = (*StubConnection)(nil)

// AcceptStream implements [dquic.Conn].
func (c *StubConnection) AcceptStream(ctx context.Context) (dquic.Stream, error) {
	// TODO: add a way to inject a stream for acceptance.
	<-ctx.Done()
	return nil, ctx.Err()
}

// AcceptUniStream implements [dquic.Conn].
func (c *StubConnection) AcceptUniStream(ctx context.Context) (dquic.ReceiveStream, error) {
	panic("stub does not support AcceptUniStream")
}

// OpenStreamSync implements [dquic.Conn].
func (c *StubConnection) OpenStreamSync(ctx context.Context) (dquic.Stream, error) {
	panic("stub does not support OpenStreamSync")
}

// OpenUniStreamSync implements [dquic.Conn].
func (c *StubConnection) OpenUniStreamSync(ctx context.Context) (dquic.SendStream, error) {
	panic("stub does not support OpenUniStreamSync")
}

// LocalAddr implements [dquic.Conn].
func (c *StubConnection) LocalAddr() net.Addr {
	return c.LocalAddrValue
}

// RemoteAddr implements [dquic.Conn].
func (c *StubConnection) RemoteAddr() net.Addr {
	return c.RemoteAddrValue
}

// CloseWithError implements [dquic.Conn].
func (c *StubConnection) CloseWithError(
	code dquic.ApplicationErrorCode, msg string,
) error {
	return nil
}

// TLSConnectionState implements [dquic.Conn].
func (c *StubConnection) TLSConnectionState() tls.ConnectionState {
	return c.TLSConnectionStateValue
}

// SendDatagram implements [dquic.Conn].
func (c *StubConnection) SendDatagram(p []byte) error {
	panic("stub does not support SendDatagram")
}

// ReceiveDatagram implements [dquic.Conn].
func (c *StubConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	panic("stub does not support ReceiveDatagram")
}

// StubNetAddr is used in [StubConnection]
// to hold the return values for
// [*StubConnection.LocalAddr] and [*StubConnection.RemoteAddr].
type StubNetAddr struct {
	NetworkValue string
	StringValue  string
}

var _ net.Addr = StubNetAddr{}

func (a StubNetAddr) Network() string { return a.NetworkValue }
func (a StubNetAddr) String() string  { return a.StringValue }
