package dbootstrap

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

// AcceptStreams accepts the disconnect and shuffle streams on c,
// using the provided deadline to encompass accepting both streams.
func AcceptStreams(
	ctx context.Context,
	c quic.Connection,
	deadline time.Time,
) (AcceptStreamsResult, error) {
	// This pattern doesn't scale beyond two streams.
	// We are definitely going to need more streams
	// for application-layer messages,
	// but that should end up happening at a different layer of the stack.

	// Set up a single context for all the streams.
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	var res AcceptStreamsResult

	// The two streams could start in any order.
	acceptedStream, err := c.AcceptStream(ctx)
	if err != nil {
		return res, fmt.Errorf("failed to accept first stream: %w", err)
	}

	if err := acceptedStream.SetReadDeadline(deadline); err != nil {
		return res, fmt.Errorf("failed to set read deadline on first stream: %w", err)
	}

	var header [2]byte
	if _, err := io.ReadFull(acceptedStream, header[:]); err != nil {
		return res, fmt.Errorf("failed to read first stream header: %w", err)
	}

	if header[0] != dproto.CurrentProtocolVersion {
		return res, fmt.Errorf("received unexpected protocol version %d in first stream header", header[0])
	}

	var expSecondType byte
	switch header[1] {
	case byte(dproto.DisconnectStreamType):
		res.Disconnect = acceptedStream
		expSecondType = byte(dproto.ShuffleStreamType)
	case byte(dproto.ShuffleStreamType):
		res.Shuffle = acceptedStream
		expSecondType = byte(dproto.DisconnectStreamType)
	default:
		return res, fmt.Errorf("received unexpected first stream type %d", header[1])
	}

	// Now we know what type to expect for the second stream.
	acceptedStream, err = c.AcceptStream(ctx)
	if err != nil {
		return res, fmt.Errorf("failed to accept second stream: %w", err)
	}

	if err := acceptedStream.SetReadDeadline(deadline); err != nil {
		return res, fmt.Errorf("failed to set read deadline on second stream: %w", err)
	}

	if _, err := io.ReadFull(acceptedStream, header[:]); err != nil {
		return res, fmt.Errorf("failed to read second stream header: %w", err)
	}

	if header[0] != dproto.CurrentProtocolVersion {
		return res, fmt.Errorf("received unexpected protocol version %d in second stream header", header[0])
	}

	if header[1] != expSecondType {
		return res, fmt.Errorf("expected second stream to be of type %d, got %d", expSecondType, header[1])
	}

	switch header[1] {
	case byte(dproto.DisconnectStreamType):
		res.Disconnect = acceptedStream
	case byte(dproto.ShuffleStreamType):
		res.Shuffle = acceptedStream
	default:
		panic(fmt.Errorf("IMPOSSIBLE: headers mishandled, accepted stream type %d", header[1]))
	}

	// Both streams have been accepted.
	return res, nil
}

type AcceptStreamsResult struct {
	Disconnect quic.Stream
	Shuffle    quic.Stream
}
