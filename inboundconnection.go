package dragon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"dragon.example/dragon/internal/dk"
	"dragon.example/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

// inboundConnection is an accepted QUIC connection
// that has not yet resolved or been closed.
type inboundConnection struct {
	log   *slog.Logger
	qConn quic.Connection

	admissionStream quic.Stream

	joinAddr string
}

func (c *inboundConnection) handleIncomingStreamHandshake(ctx context.Context) error {
	// We have just accepted an incoming QUIC connection,
	// so now we need to handle an incoming stream.
	// If the remote client is following the protocol,
	// then they will open an Admission stream first.
	s, err := c.qConn.AcceptStream(ctx)
	if err != nil {
		// Possibly a context error, but that will be handled higher in the stack.
		return fmt.Errorf("failed to accept stream: %w", err)
	}

	// Now we have accepted the stream.
	// Ensure we understand the steam type the client is requesting.
	var streamHeader [2]byte

	if err := s.SetReadDeadline(time.Now().Add(dproto.OpenStreamTimeout)); err != nil {
		return fmt.Errorf("failed to set read deadline on stream: %w", err)
	}

	if _, err := io.ReadFull(s, streamHeader[:]); err != nil {
		return fmt.Errorf("failed to read stream header: %w", err)
	}

	if streamHeader[0] != dproto.CurrentProtocolVersion {
		return fmt.Errorf("received unexpected protocol version %d in stream header", streamHeader[0])
	}

	switch streamHeader[1] {
	case dproto.AdmissionStreamType:
		c.admissionStream = s
		return c.handleStartAdmissionStream()
	default:
		return fmt.Errorf("unknown stream type %d for new incoming stream", streamHeader[1])
	}
}

func (c *inboundConnection) handleStartAdmissionStream() error {
	// We have accepted a new QUIC connection, the initial stream handshake was right,
	// and now we have to parse the first message from the remote client.
	// The first two bytes should be a type and a length.

	var tl [2]byte
	if _, err := io.ReadFull(c.admissionStream, tl[:]); err != nil {
		return fmt.Errorf("failed to read first admission stream message: %w", err)
	}

	switch tl[0] {
	case byte(dproto.JoinMessageType):
		return c.handleJoin(tl[1])

	// TODO: handle neighbor message type.

	default:
		return fmt.Errorf("invalid admission stream message type: %d", tl[0])
	}
}

func (c *inboundConnection) handleJoin(addrSz uint8) error {
	addrBuf := make([]byte, addrSz)

	if _, err := io.ReadFull(c.admissionStream, addrBuf[:]); err != nil {
		return fmt.Errorf("failed to read address from client's join message: %w", err)
	}

	// Now, we have a valid join message.
	c.joinAddr = string(addrBuf)

	return nil
}

func (c *inboundConnection) handleJoinDecision(d dk.JoinDecision) error {
	switch d {
	case dk.AcceptJoinDecision:
		return c.sendNeighborRequest()
	case dk.DisconnectJoinDecision:
		// We can just close the connection outright.
		// Since we haven't peered, we have not yet set up the disconnect stream.
		if err := c.qConn.CloseWithError(quic.ApplicationErrorCode(1), "TODO (inboundConnection.handleJoinDecision)"); err != nil {
			c.log.Info("Error closing remote connection", "err", err)
		}
		return nil
	default:
		panic(fmt.Errorf(
			"BUG: invalid join decision value: %d", d,
		))
	}
}

func (c *inboundConnection) sendNeighborRequest() error {
	s := c.admissionStream
	if err := s.SetWriteDeadline(time.Now().Add(dproto.NeighborRequestTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline for stream: %w", err)
	}

	// The neighbor request has no value,
	// so we will only send the type header.
	t := [1]byte{byte(dproto.NeighborMessageType)}
	if _, err := s.Write(t[:]); err != nil {
		return fmt.Errorf("failed to send neighbor request: %w", err)
	}

	return nil
}

func (c *inboundConnection) AsAwaitingNeighborReply() *awaitingNeighborReplyConnection {
	return &awaitingNeighborReplyConnection{
		log:   c.log,
		qConn: c.qConn,

		admissionStream: c.admissionStream,
	}
}
