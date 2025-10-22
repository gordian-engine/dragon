package dquic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
)

// ApplicationErrorCode is used for [Conn.CloseWithError].
type ApplicationErrorCode uint64

// Conn is the interface representing a QUIC connection.
//
// This is mostly a subset of the methods on [*quic.Conn],
// only referencing the methods used in dragon.
type Conn interface {
	AcceptStream(context.Context) (Stream, error)
	AcceptUniStream(context.Context) (ReceiveStream, error)

	// We never call OpenStream or OpenUniStream in dragon.
	// We only call the Sync variations of those methods.

	OpenStreamSync(context.Context) (Stream, error)
	OpenUniStreamSync(context.Context) (SendStream, error)

	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)

	CloseWithError(
		code ApplicationErrorCode, msg string,
	) error

	// This diverges from the quic.Conn interface.
	// Instead of exposing their entire connection state,
	// we only expose the TLS details that we use occasionally in dragon.
	TLSConnectionState() tls.ConnectionState

	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

var _ Conn = ConnAdapter{}

// ConnAdapter wraps a [*quic.Conn], implementing the [Conn] interface.
//
// Create an instance with [WrapConn].
type ConnAdapter struct {
	qc *quic.Conn
}

// WrapConn wraps the given connection,
// returning a value implementing [Conn].
func WrapConn(qc *quic.Conn) ConnAdapter {
	return ConnAdapter{qc: qc}
}

func (c ConnAdapter) AcceptStream(ctx context.Context) (Stream, error) {
	s, err := c.qc.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return WrapStream(s), nil
}

func (c ConnAdapter) AcceptUniStream(ctx context.Context) (ReceiveStream, error) {
	s, err := c.qc.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	return WrapReceiveStream(s), nil
}

func (c ConnAdapter) OpenStreamSync(ctx context.Context) (Stream, error) {
	s, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return WrapStream(s), err
}

func (c ConnAdapter) OpenUniStreamSync(ctx context.Context) (SendStream, error) {
	s, err := c.qc.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	return WrapSendStream(s), nil
}

func (c ConnAdapter) SendDatagram(p []byte) error {
	return c.qc.SendDatagram(p)
}

func (c ConnAdapter) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.qc.ReceiveDatagram(ctx)
}

func (c ConnAdapter) CloseWithError(
	code ApplicationErrorCode, msg string,
) error {
	if (code >> 62) > 0 {
		panic(fmt.Errorf(
			"BUG: application error code must fit in 62 bits (got 0x%x)", code,
		))
	}
	return c.qc.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

func (c ConnAdapter) TLSConnectionState() tls.ConnectionState {
	return c.qc.ConnectionState().TLS
}

func (c ConnAdapter) LocalAddr() net.Addr { return c.qc.LocalAddr() }

func (c ConnAdapter) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }
