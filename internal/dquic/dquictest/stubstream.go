package dquictest

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type StubStream struct {
	StubReceiveStream
	StubSendStream

	// For now the stream ID is just a global number
	// incremented with each call to NewStubStream,
	// but we could be a lot smarter about the values,
	// if it turns out anything in dragon depends on it.
	streamID quic.StreamID
}

var globalStreamID int64

func NewStubStream(ctx context.Context) *StubStream {
	sid := atomic.AddInt64(&globalStreamID, 1)
	return &StubStream{
		StubSendStream: StubSendStream{
			ContextValue: ctx,
			streamID:     quic.StreamID(sid),
		},
		StubReceiveStream: StubReceiveStream{
			ContextValue: ctx,
			streamID:     quic.StreamID(sid),
		},
		streamID: quic.StreamID(sid),
	}
}

var _ quic.Stream = (*StubStream)(nil)

func (s *StubStream) SetDeadline(time.Time) error {
	return nil
}

func (s *StubStream) StreamID() quic.StreamID {
	return s.streamID
}

type StubReceiveStream struct {
	ContextValue context.Context

	streamID quic.StreamID
}

func (s *StubReceiveStream) StreamID() quic.StreamID {
	return s.streamID
}

func (s *StubReceiveStream) Read(p []byte) (int, error) {
	// For now, we will just block on the context.
	<-s.ContextValue.Done()
	return 0, s.ContextValue.Err()
}

func (s *StubReceiveStream) CancelRead(code quic.StreamErrorCode) {}

func (s *StubReceiveStream) SetReadDeadline(time.Time) error { return nil }

var _ quic.ReceiveStream = (*StubReceiveStream)(nil)

type StubSendStream struct {
	ContextValue context.Context

	streamID quic.StreamID
}

var _ quic.SendStream = (*StubSendStream)(nil)

func NewStubSendStream() *StubSendStream {
	sid := atomic.AddInt64(&globalStreamID, 1)
	return &StubSendStream{
		streamID: quic.StreamID(sid),
	}
}

func (s *StubSendStream) StreamID() quic.StreamID {
	return s.streamID
}

func (s *StubSendStream) Write(p []byte) (int, error) {
	// For now, just act like we accepted the write.
	// But maybe it would be better to block here and offer some coordination?
	return len(p), nil
}

func (s *StubSendStream) Close() error { return nil }

func (s *StubSendStream) CancelWrite(code quic.StreamErrorCode) {}

func (s *StubSendStream) Context() context.Context {
	if s.ContextValue == nil {
		return context.Background()
	}

	return s.ContextValue
}

func (s *StubSendStream) SetWriteDeadline(time.Time) error { return nil }
