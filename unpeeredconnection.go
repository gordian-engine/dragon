package dragon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"dragon.example/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

// UnpeeredConnection is an initialized connection in the network.
// We have opened a QUIC connection to another node,
// but we have not yet established the protocol-level peering.
//
// Create an UnpeeredConnection through [(*Node).DialPeer].
type UnpeeredConnection struct {
	log   *slog.Logger
	qConn quic.Connection

	streams streams

	node *Node
}

// Join sends a Join message to the remote peer.
// This is expected to be the first method called on a new UnpeeredConnection.
// It does not happen automatically after [(*Node).DialPeer];
// in other cases, the first method could be a neighbor request.
//
// Calling Join sets up the admission QUIC stream to handle requests
// related to admission into the peer-to-peer network.
//
// If the Join message reaches the contact node successfully,
// the contact node may send a Neighbor request,
// or after the contact node sends out ForwardJoin messages,
// other nodes may themselves send Neighbor requests.
//
// There is no explicit acknowledgement to a Join request.
func (c *UnpeeredConnection) Join(ctx context.Context) error {
	// The peer who opened the connection is considered the client.
	// On attempting to join, we open a bidirectional stream for
	// Join and Neighbor streams.

	jm := dproto.JoinMessage{
		Addr: "TODO",
	}
	msg := jm.OpenStreamAndJoinBytes()

	admStream, err := c.qConn.OpenStream()
	if err != nil {
		return fmt.Errorf("Join: failed to open stream: %w", err)
	}
	c.streams.Admission = admStream

	// Set write deadline, so that we don't block for a long time
	// in case writing the stream blocks for whatever reason.
	if err := admStream.SetWriteDeadline(time.Now().Add(dproto.OpenStreamTimeout)); err != nil {
		return fmt.Errorf("Join: failed to set stream deadline: %w", err)
	}

	// Send both the open stream header and the join message.
	if _, err := admStream.Write(msg); err != nil {
		return fmt.Errorf("Join: failed to write stream header and join message: %w", err)
	}

	// Now we have to wait.
	// We expect one of two outcomes on this stream once we've sent the join message:
	//  1. The remote end closes because they will not accept us into their active set right now.
	//  2. The remote end sends us a Neighbor message, and we have to ack it.
	//
	// And regardless of this stream,
	// the remote end should begin sending ForwardJoin messages out to the network,
	// so hopefully we get some new incoming Neighbor requests soon.
	return nil
}

// Close closes the connection.
// According to the quic docs, this supposed to not be called concurrently with other functions.
// The docs also state the reason will be sent to the peer,
// so presumably that is why the Close method must require the argument.
func (c *UnpeeredConnection) Close(code uint64, reason string) error {
	return c.qConn.CloseWithError(quic.ApplicationErrorCode(code), reason)
}

// ClosedError returns nil if the connection is still alive,
// or an error indicating why the connection is closed.
func (c *UnpeeredConnection) ClosedError() error {
	return context.Cause(c.qConn.Context())
}
