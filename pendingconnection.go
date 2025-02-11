package dragon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"dragon.example/dragon/internal/dpmsg"
	"github.com/quic-go/quic-go"
)

// pendingConnection is an accepted QUIC connection
// that has not yet resolved or been closed.
type pendingConnection struct {
	log   *slog.Logger
	qConn quic.Connection

	admissionStream quic.Stream

	joinAddr string
}

func (c *pendingConnection) handleIncomingStreamHandshake(ctx context.Context) error {
	// We have just accepted an incoming QUIC connection,
	// so now we need to handle an incoming stream.
	// If the remote client is following the protocol,
	// then they will open an Admission stream first.
	s, err := c.qConn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("failed to accept stream: %w", err)
	}

	// Now we have accepted the stream.
	// Ensure we understand the steam type the client is requesting.
	var streamHeader [2]byte

	if err := s.SetReadDeadline(time.Now().Add(dpmsg.OpenStreamTimeout)); err != nil {
		return fmt.Errorf("failed to set read deadline on stream: %w", err)
	}

	if _, err := s.Read(streamHeader[:]); err != nil {
		return fmt.Errorf("failed to read stream header: %w", err)
	}

	if streamHeader[0] != dpmsg.CurrentProtocolVersion {
		return fmt.Errorf("received unexpected protocol version %d in stream header", streamHeader[0])
	}

	switch streamHeader[1] {
	case dpmsg.AdmissionStreamType:
		c.admissionStream = s
		return c.handleStartAdmissionStream(ctx)
	default:
		return fmt.Errorf("unknown stream type %d", streamHeader[1])
	}
}

func (c *pendingConnection) handleStartAdmissionStream(ctx context.Context) error {
	// We have accepted a new QUIC connection, the initial stream handshake was right,
	// and now we have to parse the first message from the remote client.
	// The first two bytes should be a type and a length.

	var tl [2]byte
	if _, err := c.admissionStream.Read(tl[:]); err != nil {
		return fmt.Errorf("failed to read first admission stream message: %w", err)
	}

	switch tl[0] {
	case byte(dpmsg.JoinMessageType):
		return c.handleJoin(tl[1])

	default:
		return fmt.Errorf("invalid admission stream message type: %d", tl[0])
	}
}

func (c *pendingConnection) handleJoin(addrSz uint8) error {
	addrBuf := make([]byte, addrSz)

	if _, err := c.admissionStream.Read(addrBuf[:]); err != nil {
		return fmt.Errorf("failed to read address from client's join message: %w", err)
	}

	// Now, we have a valid join message.
	c.joinAddr = string(addrBuf)

	return nil
}
