package dquic

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go"
)

// StreamErrorCode is used for
// [ReceiveStream.CancelRead] and [SendStream.CancelWrite],
// to inform the peer of why the stream is canceled.
type StreamErrorCode uint64

// ReceiveStream is the read-only version of a [Stream].
type ReceiveStream interface {
	Read([]byte) (int, error)
	CancelRead(StreamErrorCode)

	SetReadDeadline(time.Time) error

	// StreamID method omitted until we need it.
}

// WrapReceiveStream wraps s into a ReceiveStreamAdapter,
// satifying the [ReceiveStream] interface.
func WrapReceiveStream(s quic.ReceiveStream) ReceiveStreamAdapter {
	return ReceiveStreamAdapter{s: s}
}

// ReceiveStreamAdapter wraps a [quic.ReceiveStream]
// to satisfy the [ReceiveStream] interface.
// Use [WrapReceiveStream] to create an instance.
type ReceiveStreamAdapter struct {
	s quic.ReceiveStream
}

func (a ReceiveStreamAdapter) Read(p []byte) (int, error) {
	return a.s.Read(p)
}

func (a ReceiveStreamAdapter) CancelRead(code StreamErrorCode) {
	if (code >> 62) > 0 {
		panic(fmt.Errorf(
			"BUG: stream error code must fit in 62 bits (got 0x%x)", code,
		))
	}
	a.s.CancelRead(quic.StreamErrorCode(code))
}

func (a ReceiveStreamAdapter) SetReadDeadline(t time.Time) error {
	return a.s.SetReadDeadline(t)
}

// SendStream is the write-only version of a [Stream].
type SendStream interface {
	Write([]byte) (int, error)
	CancelWrite(StreamErrorCode)

	Close() error

	SetWriteDeadline(t time.Time) error
}

// WrapSendStream wraps s into a SendStreamAdapter,
// satifying the [SendStream] interface.
func WrapSendStream(s quic.SendStream) SendStreamAdapter {
	return SendStreamAdapter{s: s}
}

// SendStreamAdapter wraps a [quic.SendStream]
// to satisfy the [SendStream] interface.
// Use [WrapSendStream] to create an instance.
type SendStreamAdapter struct {
	s quic.SendStream
}

func (a SendStreamAdapter) Write(p []byte) (int, error) {
	return a.s.Write(p)
}

func (a SendStreamAdapter) CancelWrite(code StreamErrorCode) {
	if (code >> 62) > 0 {
		panic(fmt.Errorf(
			"BUG: stream error code must fit in 62 bits (got 0x%x)", code,
		))
	}
	a.s.CancelWrite(quic.StreamErrorCode(code))
}

func (a SendStreamAdapter) Close() error {
	return a.s.Close()
}

func (a SendStreamAdapter) SetWriteDeadline(t time.Time) error {
	return a.s.SetWriteDeadline(t)
}

// Stream is a readable and writable QUIC stream.
type Stream interface {
	SendStream
	ReceiveStream

	// General SetDeadline omitted until we need it.
}

type StreamAdapter struct {
	s quic.Stream
}

func WrapStream(s quic.Stream) StreamAdapter {
	return StreamAdapter{s: s}
}

func (a StreamAdapter) Read(p []byte) (int, error) {
	return a.s.Read(p)
}

func (a StreamAdapter) CancelRead(code StreamErrorCode) {
	if (code >> 62) > 0 {
		panic(fmt.Errorf(
			"BUG: stream error code must fit in 62 bits (got 0x%x)", code,
		))
	}
	a.s.CancelRead(quic.StreamErrorCode(code))
}

func (a StreamAdapter) SetReadDeadline(t time.Time) error {
	return a.s.SetReadDeadline(t)
}

func (a StreamAdapter) Write(p []byte) (int, error) {
	return a.s.Write(p)
}

func (a StreamAdapter) CancelWrite(code StreamErrorCode) {
	if (code >> 62) > 0 {
		panic(fmt.Errorf(
			"BUG: stream error code must fit in 62 bits (got 0x%x)", code,
		))
	}
	a.s.CancelWrite(quic.StreamErrorCode(code))
}

func (a StreamAdapter) Close() error {
	return a.s.Close()
}

func (a StreamAdapter) SetWriteDeadline(t time.Time) error {
	return a.s.SetWriteDeadline(t)
}
