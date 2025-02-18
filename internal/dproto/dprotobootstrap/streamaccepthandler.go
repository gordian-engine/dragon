package dprotobootstrap

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"dragon.example/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type streamAcceptHandler struct {
	OuterLog *slog.Logger

	Cfg *OutgoingJoinConfig
}

func (h streamAcceptHandler) Handle(
	ctx context.Context, c quic.Connection, res *Result,
) (streamHandler, error) {
	// This pattern doesn't scale beyond two streams.
	// We are definitely going to need more streams
	// for application-layer messages,
	// but that will end up happening at a different layer of the stack.

	// Set the deadline once because we are going to use it a few times.
	deadline := h.Cfg.NowFn().Add(h.Cfg.AcceptStreamsTimeout)

	// One context with deadline for accepting both of the streams.
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// The two streams could start in any order.
	acceptedStream, err := c.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to accept first stream: %w", err)
	}

	if err := acceptedStream.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set read deadline on first stream: %w", err)
	}

	var header [2]byte
	if _, err := io.ReadFull(acceptedStream, header[:]); err != nil {
		return nil, fmt.Errorf("failed to read stream header: %w", err)
	}

	if header[0] != dproto.CurrentProtocolVersion {
		return nil, fmt.Errorf("received unexpected protocol version %d in stream header", header[0])
	}

	var disconnectStream, shuffleStream quic.Stream

	var expSecondType byte
	switch header[1] {
	case byte(dproto.DisconnectStreamType):
		disconnectStream = acceptedStream
		expSecondType = byte(dproto.ShuffleStreamType)
	case byte(dproto.ShuffleStreamType):
		shuffleStream = acceptedStream
		expSecondType = byte(dproto.DisconnectStreamType)
	default:
		return nil, fmt.Errorf("received unexpected stream type %d", header[1])
	}

	// Now we know what type to expect for the second stream.
	acceptedStream, err = c.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to accept second stream: %w", err)
	}

	if err := acceptedStream.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set read deadline on stream: %w", err)
	}

	if _, err := io.ReadFull(acceptedStream, header[:]); err != nil {
		return nil, fmt.Errorf("failed to read stream header: %w", err)
	}

	if header[0] != dproto.CurrentProtocolVersion {
		return nil, fmt.Errorf("received unexpected protocol version %d in stream header", header[0])
	}

	if header[1] != expSecondType {
		return nil, fmt.Errorf("expected second stream to be of type %d, got %d", expSecondType, header[1])
	}

	switch header[1] {
	case byte(dproto.DisconnectStreamType):
		disconnectStream = acceptedStream
	case byte(dproto.ShuffleStreamType):
		shuffleStream = acceptedStream
	default:
		panic(fmt.Errorf("IMPOSSIBLE: headers mishandled, accepted stream type %d", header[1]))
	}

	// We've set both the disconnect and shuffle streams,
	// and we didn't get an error sending them,
	// so we should be safe to assume the remote end is still connected.

	res.DisconnectStream = disconnectStream
	res.ShuffleStream = shuffleStream

	// We return a nil error and a nil handler here
	// because we have reached the terminal state of the admission stream setup.
	return nil, nil
}

func (h streamAcceptHandler) Name() string {
	return "Stream Accept"
}
