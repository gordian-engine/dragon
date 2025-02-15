package dragon

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"dragon.example/dragon/dca"
	"dragon.example/dragon/internal/dcrypto"
	"dragon.example/dragon/internal/dk"
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

	certRemoved <-chan struct{}

	admissionStream  quic.Stream
	disconnectStream quic.Stream
	shuffleStream    quic.Stream

	n *Node
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
	// On attempting to join, we open a bidirectional admission stream.
	// The first message on the stream must be Join or Neighbor;
	// in this method, the message is Join of course.

	jm := dproto.JoinMessage{
		Addr: c.n.advertiseAddr,
	}
	jm.SetTimestamp(time.Now())

	if err := c.signJoinMessage(&jm); err != nil {
		return fmt.Errorf("Join: failed to sign join message: %w", err)
	}

	msg := jm.OpenStreamAndJoinBytes()

	admStream, err := c.qConn.OpenStream()
	if err != nil {
		return fmt.Errorf("Join: failed to open stream: %w", err)
	}
	c.admissionStream = admStream

	// Set write deadline, so that we don't block for a long time
	// in case writing the stream blocks for whatever reason.
	if err := admStream.SetWriteDeadline(time.Now().Add(dproto.OpenStreamTimeout)); err != nil {
		return fmt.Errorf("Join: failed to set stream write deadline: %w", err)
	}

	// Send both the open stream header and the join message.
	if _, err := admStream.Write(msg); err != nil {
		return fmt.Errorf("Join: failed to write stream header and join message: %w", err)
	}

	// We expect one of two outcomes on this stream once we've sent the join message:
	//  1. The remote end closes because they will not accept us into their active set right now.
	//  2. The remote end sends us a Neighbor message, and we have to ack it.
	//
	// And regardless of this stream,
	// the remote end should begin sending ForwardJoin messages out to the network,
	// so hopefully we get some new incoming Neighbor requests soon.
	//
	// Attempt to read from the stream,
	// optimistically looking for a neighbor message.

	if err := admStream.SetReadDeadline(time.Now().Add(dproto.AwaitNeighborTimeout)); err != nil {
		return fmt.Errorf("Join: failed to set stream read deadline: %w", err)
	}

	// The neighbor request is just the single byte.
	var nReq [1]byte
	if _, err := io.ReadFull(admStream, nReq[:]); err != nil {
		return fmt.Errorf("Join: failed to read neighbor reply: %w", err)
	}
	if nReq[0] != byte(dproto.NeighborMessageType) {
		return fmt.Errorf("Join: expected neighbor message but got %d", nReq)
	}

	// After receiving the neighbor request, we can send our reply.
	// TODO: this should consult the kernel to determine
	// if we actually do want to accept the neighbor;
	// if this was the slowest of several responders,
	// we could have filled our active set already, for instance.
	nReply := dproto.NeighborReplyMessage{Accepted: true}

	if err := admStream.SetWriteDeadline(time.Now().Add(dproto.OpenStreamTimeout)); err != nil {
		return fmt.Errorf("Join: failed to set stream write deadline: %w", err)
	}
	if _, err := admStream.Write(nReply.Bytes()); err != nil {
		return fmt.Errorf("Join: failed to send neighbor response: %w", err)
	}

	if err := c.acceptProtocolStreams(ctx); err != nil {
		return fmt.Errorf("Join: accepting protocol streams: %w", err)
	}

	// Since we have accepted the protocol streams successfully,
	// we can inform the kernel that we have a peering.

	pResp := make(chan dk.NewPeeringResponse, 1)
	req := dk.NewPeeringRequest{
		QuicConn: c.qConn,

		AdmissionStream:  c.admissionStream,
		DisconnectStream: c.disconnectStream,
		ShuffleStream:    c.shuffleStream,

		Resp: pResp,
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)

	case <-c.certRemoved:
		return dca.ErrCertRemoved

	case c.n.k.NewPeeringRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return context.Cause(ctx)

	case <-c.certRemoved:
		return dca.ErrCertRemoved

	case resp := <-pResp:
		if resp.RejectReason != "" {
			// Last minute issue with adding the connection.
			if err := c.qConn.CloseWithError(1, "TODO: peering rejected: "+resp.RejectReason); err != nil {
				c.log.Debug("Failed to close connection", "err", err)
			}

			return fmt.Errorf("failed to join due to kernel rejecting peering: %s", resp.RejectReason)
		}

		// Otherwise it was accepted, and the Join is complete.
		return nil
	}
}

func (c *UnpeeredConnection) acceptProtocolStreams(ctx context.Context) error {
	// The main thing I don't like about this method is that
	// we are completely ignoring the primary stream at this point.
	//
	// Secondarily, this pattern doesn't scale beyond two streams,
	// and we are definitely going to need more streams
	// for application-layer messages.
	//
	// It seems like we could optimistically run stream handler goroutines
	// as we iterate through this, though.

	// Set the deadline once because we are going to use it a few times.
	deadline := time.Now().Add(dproto.ReceiveInitialStreamsTimeout)

	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// The two streams could start in any order.
	s, err := c.qConn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("failed to accept first stream: %w", err)
	}

	if err := s.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set read deadline on stream: %w", err)
	}

	var header [2]byte
	if _, err := io.ReadFull(s, header[:]); err != nil {
		return fmt.Errorf("failed to read stream header: %w", err)
	}

	if header[0] != dproto.CurrentProtocolVersion {
		return fmt.Errorf("received unexpected protocol version %d in stream header", header[0])
	}

	var expSecondType byte
	switch header[1] {
	case byte(dproto.DisconnectStreamType):
		c.disconnectStream = s
		expSecondType = byte(dproto.ShuffleStreamType)
	case byte(dproto.ShuffleStreamType):
		c.shuffleStream = s
		expSecondType = byte(dproto.DisconnectStreamType)
	default:
		return fmt.Errorf("received unexpected stream type %d", header[1])
	}

	// Now we know what type to expect for the second stream.
	s, err = c.qConn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("failed to accept second stream: %w", err)
	}

	if err := s.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set read deadline on stream: %w", err)
	}

	if _, err := io.ReadFull(s, header[:]); err != nil {
		return fmt.Errorf("failed to read stream header: %w", err)
	}

	if header[0] != dproto.CurrentProtocolVersion {
		return fmt.Errorf("received unexpected protocol version %d in stream header", header[0])
	}

	if header[1] != expSecondType {
		return fmt.Errorf("expected second stream to be of type %d, got %d", expSecondType, header[1])
	}

	switch header[1] {
	case byte(dproto.DisconnectStreamType):
		c.disconnectStream = s
	case byte(dproto.ShuffleStreamType):
		c.shuffleStream = s
	default:
		panic(fmt.Errorf("IMPOSSIBLE: headers mishandled, accepted stream type %d", header[1]))
	}

	// We've set both the disconnect and shuffle streams,
	// and we didn't get an error sending them,
	// so we should be safe to assume the remote end is still connected.

	return nil
}

func (c *UnpeeredConnection) signJoinMessage(jm *dproto.JoinMessage) error {
	tlsConf := c.n.baseTLSConf
	if len(tlsConf.Certificates) == 0 {
		return errors.New("no certificates found in TLS configuration")
	}

	joinSignContent := jm.AppendSignContent(nil)

	cert := tlsConf.Certificates[0]
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate to sign join message: %w", err)
		}
		cert.Leaf = leaf
	}

	sig, err := dcrypto.SignMessageWithTLSCert(joinSignContent, cert)
	if err != nil {
		return fmt.Errorf("failed to sign join message: %w", err)
	}

	jm.Signature = sig
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
