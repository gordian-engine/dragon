package dquictest

import (
	"context"
	"io"
	"time"

	"github.com/gordian-engine/dragon/dquic"
)

type StubStream struct {
	StubReceiveStream
	StubSendStream
}

func NewStubStream(ctx context.Context) *StubStream {
	return new(StubStream)
}

var _ dquic.Stream = (*StubStream)(nil)

type StubReceiveStream struct{}

func (s *StubReceiveStream) Read(p []byte) (int, error) {
	// For now, we will just say nothing is available to read.
	return 0, io.EOF
}

func (s *StubReceiveStream) CancelRead(code dquic.StreamErrorCode) {}

func (s *StubReceiveStream) SetReadDeadline(time.Time) error { return nil }

var _ dquic.ReceiveStream = (*StubReceiveStream)(nil)

type StubSendStream struct{}

var _ dquic.SendStream = (*StubSendStream)(nil)

func NewStubSendStream() *StubSendStream {
	return new(StubSendStream)
}

func (s *StubSendStream) Write(p []byte) (int, error) {
	// For now, just act like we accepted the write.
	// But maybe it would be better to block here and offer some coordination?
	return len(p), nil
}

func (s *StubSendStream) Close() error { return nil }

func (s *StubSendStream) CancelWrite(code dquic.StreamErrorCode) {}

func (s *StubSendStream) SetWriteDeadline(time.Time) error { return nil }
