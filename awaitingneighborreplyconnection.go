package dragon

import (
	"context"
	"fmt"
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

	admissionStream quic.Stream
}

// AwaitNeighborReply blocks temporarily while waiting for the remote end of the admission stream
func (c *awaitingNeighborReplyConnection) AwaitNeighborReply(ctx context.Context) error {
	s := c.admissionStream
	if err := s.SetReadDeadline(time.Now().Add(dproto.AwaitNeighborTimeout)); err != nil {
		return fmt.Errorf("failed to set read deadline on stream: %w", err)
	}

	panic("TODO: finish awaiting neighbor reply")
}
