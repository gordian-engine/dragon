package dragon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"dragon.example/dragon/deval"
	"dragon.example/dragon/internal/dk"
	"dragon.example/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

// inboundConnection is an accepted QUIC connection
// that has not yet resolved or been closed.
type inboundConnection struct {
	log   *slog.Logger
	qConn quic.Connection

	k *dk.Kernel

	admissionStream quic.Stream

	joinAddr string
}

func (c *inboundConnection) HandleIncomingStream(ctx context.Context) error {
	if err := c.handleIncomingStreamHandshake(ctx); err != nil {
		// Error already wrapped properly.
		return err
	}

	if len(c.joinAddr) > 0 {
		// We have a join message.

		// Assume non-nil error was already wrapped properly.
		return c.handleJoinRequest(ctx)
	}

	panic(fmt.Errorf("TODO: handle neighbor message on incoming stream"))
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

	var typeBuf [1]byte
	if _, err := io.ReadFull(c.admissionStream, typeBuf[:]); err != nil {
		return fmt.Errorf("failed to read first admission stream message: %w", err)
	}

	switch typeBuf[0] {
	case byte(dproto.JoinMessageType):
		// TODO: do we need to set another read timeout here,
		// or is it okay to rely on the already-set timeout?

		var jm dproto.JoinMessage
		if err := jm.Decode(c.admissionStream); err != nil {
			return fmt.Errorf("failed to decode join message from admission stream: %w", err)
		}

		// Now, we have a join message that is the right size.
		// The kernel is going to be responsible for deciding
		// whether we actually accept this join.
		c.joinAddr = jm.Addr

		// TODO: validate timestamp and signature.

		return nil

	// TODO: handle neighbor message type.

	default:
		return fmt.Errorf("invalid admission stream message type: %d", typeBuf[0])
	}
}

func (c *inboundConnection) handleJoinRequest(ctx context.Context) error {
	peer := deval.Peer{
		TLS:        c.qConn.ConnectionState().TLS,
		LocalAddr:  c.qConn.LocalAddr(),
		RemoteAddr: c.qConn.RemoteAddr(),
	}
	respCh := make(chan dk.JoinResponse, 1)
	req := dk.JoinRequest{
		Peer: peer,
		Resp: respCh,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while sending join request to kernel: %w", context.Cause(ctx),
		)
	case c.k.JoinRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while awaiting join response from kernel: %w", context.Cause(ctx),
		)
	case resp := <-respCh:
		// The kernel responded with the decision on what to do with the incoming join.
		if err := c.handleJoinDecision(resp.Decision); err != nil {
			return fmt.Errorf(
				"failed while handling join decision %v: %w",
				resp.Decision, err,
			)
		}

		// Since the inbound connection handled the join decision,
		// we either closed the connection and are discarding it,
		// or the connection has an outgoing neighbor request.

		if resp.Decision == dk.DisconnectJoinDecision {
			// Then we already closed the connection,
			// so we can stop here.
			return nil
		}

		if resp.Decision != dk.AcceptJoinDecision {
			panic(fmt.Errorf(
				"IMPOSSIBLE: kernel returned invalid join decision %v", resp.Decision,
			))
		}

		// It was an accept decision,
		// so we already sent a Neighbor request to the peer.
		// Now we have to block waiting for the neighbor reply.
		ac := c.AsAwaitingNeighborReply()
		if err := ac.AwaitNeighborReply(ctx); err != nil {
			return fmt.Errorf("failed waiting for neighbor reply: %w", err)
		}

		// Now we have the neighbor reply,
		// so we have to initialize the remaining streams,
		// which is our counter-acknowledgement that fully initializes the connection.
		if err := ac.FinishInitializingStreams(ctx); err != nil {
			return fmt.Errorf("failed initializing streams to finalize peering: %w", err)
		}

		// Finally, the streams are initialized,
		// so we can pass the connection to the kernel now.
		pResp := make(chan dk.NewPeeringResponse, 1)
		req := dk.NewPeeringRequest{
			QuicConn: ac.qConn,

			AdmissionStream:  ac.admissionStream,
			DisconnectStream: ac.disconnectStream,
			ShuffleStream:    ac.shuffleStream,

			Resp: pResp,
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"context cancelled while sending peering request to kernel: %w",
				context.Cause(ctx),
			)

		case c.k.NewPeeringRequests <- req:
			// Okay.
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"context cancelled while awaiting peering response from kernel: %w",
				context.Cause(ctx),
			)
		case resp := <-pResp:
			if resp.RejectReason != "" {
				// Last minute issue with adding the connection.
				// We are going to close the connection directly here.
				if err := c.qConn.CloseWithError(1, "TODO: peering rejected: "+resp.RejectReason); err != nil {
					ac.log.Debug("Failed to close connection", "err", err)
				}
			}

			return nil
		}
	}
}

func (c *inboundConnection) handleJoinDecision(d dk.JoinDecision) error {
	switch d {
	case dk.AcceptJoinDecision:
		return c.sendNeighborRequest()
	case dk.DisconnectJoinDecision:
		// We can just close the connection outright.
		if err := c.qConn.CloseWithError(quic.ApplicationErrorCode(1), "TODO (inboundConnection.handleJoinDecision)"); err != nil {
			c.log.Info("Error closing remote connection", "err", err)
		}

		// And we return nil here since the connection has been successfully handled.
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
