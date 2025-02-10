package dragon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"dragon.example/dragon/internal/dpmsg"
	"github.com/quic-go/quic-go"
)

// Connection is a peer-to-peer connection in the network.
//
// Create a Connection through [(*Node).DialPeer].
type Connection struct {
	log  *slog.Logger
	conn quic.Connection
}

// Join sends a Join message to the connected peer.
// This is expected to be the first message sent on a new connection.
//
// If the Join message reaches the contact node successfully,
// the contact node may send a Neighbor request,
// or after the contact node sends out ForwardJoin messages,
// other nodes may themselves send Neighbor requests.
//
// There is no explicit acknowledgement to a Join request.
func (c *Connection) Join(ctx context.Context) error {
	// Unidirectional stream because we don't expect a response.
	s, err := c.conn.OpenUniStream()
	if err != nil {
		return fmt.Errorf("Join: failed to open stream: %w", err)
	}

	defer func() {
		if err := s.Close(); err != nil {
			c.log.Info("Error closing join stream", "err", err)
		}
	}()

	// This is a reliable stream, so set a write deadline.
	// The upcoming write will block,
	// so setting the deadline avoids having to run another goroutine to manage this.
	// Moreover, the quic.SendStream docs say not to call Close concurrently with Write.
	if err := s.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return fmt.Errorf("Join: failed to set stream deadline: %w", err)
	}

	// TLV-encode the join message.
	msg := []byte{byte(dpmsg.JoinMessageType), 0}
	if _, err := s.Write(msg); err != nil {
		return fmt.Errorf("Join: failed to write message: %w", err)
	}

	// The stream is closed from the early defer, so we are done here.
	return nil
}

// Close closes the connection.
// According to the quic docs, this supposed to not be called concurrently with other functions.
// The docs also state the reason will be sent to the peer,
// so presumably that is why the Close method must require the argument.
func (c *Connection) Close(code uint64, reason string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), reason)
}
