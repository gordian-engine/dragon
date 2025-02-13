package dragon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"dragon.example/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

// awaitingNeighborReplyConnection wraps a QUIC connection
// where we have sent a Neighbor message and
// we are waiting for the remote end to send a NeighborReply message.
//
// The logic in this step does not distinguish a client from a server,
// as it is possible that a client opened a new connection
// and sent a Join request, and we as the server sent a Neighbor message;
// or the client opened a new connection and immediately sent a Neighbor message.
type awaitingNeighborReplyConnection struct {
	log   *slog.Logger
	qConn quic.Connection

	admissionStream  quic.Stream
	disconnectStream quic.Stream
	shuffleStream    quic.Stream
}

// AwaitNeighborReply blocks temporarily while waiting for the remote end of the admission stream
//
// If we received a positive reply, this method returns nil.
// Any other outcome is an error.
func (c *awaitingNeighborReplyConnection) AwaitNeighborReply(ctx context.Context) error {
	s := c.admissionStream
	if err := s.SetReadDeadline(time.Now().Add(dproto.AwaitNeighborTimeout)); err != nil {
		return fmt.Errorf("failed to set read deadline on stream: %w", err)
	}

	var tl [2]byte
	if _, err := io.ReadFull(s, tl[:]); err != nil {
		return fmt.Errorf("failed to receive neighbor reply message: %w", err)
	}

	if tl[0] != byte(dproto.NeighborReplyMessageType) {
		return fmt.Errorf("expected neighbor reply message type, got %d", tl[0])
	}

	switch tl[1] {
	case 0:
		// Not accepted.
		// If we return an error here, the node will close our end
		// (even though the remote end should be closing theirs too).
		return errors.New("received neighbor reply indicating rejection")
	case 1:
		// Accepted.
		return nil
	default:
		return fmt.Errorf("received invalid neighbor reply byte 0x%x", tl[1])
	}
}

// FinishInitializingStreams opens the disconnect and shuffle streams.
// This is intended to be called after we have received the neighbor reply,
// which is our signal to that node, that we have accepted the neighbor reply.
// After this, the connection and its streams are ready to go.
func (c *awaitingNeighborReplyConnection) FinishInitializingStreams(ctx context.Context) error {
	// It doesn't really matter what order we open the streams,
	// but we'll do Disconnect first since that happens to be declared first in the constants.

	deadline := time.Now().Add(dproto.InitializeStreamsTimeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	ds, err := c.qConn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("failed to open stream for disconnect info: %w", err)
	}

	if err := ds.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set write deadline for disconnect stream: %w", err)
	}
	if _, err := ds.Write([]byte{dproto.CurrentProtocolVersion, byte(dproto.DisconnectStreamType)}); err != nil {
		return fmt.Errorf("failed to write disconnect stream header: %w", err)
	}

	c.disconnectStream = ds

	ss, err := c.qConn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("failed to open stream for shuffle info: %w", err)
	}

	if err := ss.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set write deadline for shuffle stream: %w", err)
	}
	if _, err := ss.Write([]byte{dproto.CurrentProtocolVersion, byte(dproto.ShuffleStreamType)}); err != nil {
		return fmt.Errorf("failed to write shuffle stream header: %w", err)
	}

	c.shuffleStream = ss

	return nil
}
