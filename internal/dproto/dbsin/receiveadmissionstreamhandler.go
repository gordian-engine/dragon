package dbsin

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"dragon.example/dragon/internal/dcrypto"
	"dragon.example/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

// receiveAdmisisonStreamHandler handles receiving initial data
// on a newly opened admission stream.
type receiveAdmissionStreamHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h receiveAdmissionStreamHandler) Handle(
	ctx context.Context, c quic.Connection, res *IncomingResult,
) (incomingStreamHandler, error) {
	// Not setting a deadline on these reads;
	// acceptIncomingStreamHandler set a read deadline
	// for the stream headers, and we rely on that value.

	s := res.AdmissionStream
	var typeBuf [1]byte
	if _, err := io.ReadFull(s, typeBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read first admission stream message")
	}

	switch typeBuf[0] {
	case byte(dproto.JoinMessageType):
		// Returned error will be wrapped properly.
		return nil, h.handleJoinMessage(res)

	// TODO: handle Neighbor message type.

	default:
		return nil, fmt.Errorf("invalid admission stream message type: %d", typeBuf[0])
	}
}

func (h receiveAdmissionStreamHandler) handleJoinMessage(
	res *IncomingResult,
) error {
	// Still relying on the earlier set read deadline.
	var jm dproto.JoinMessage
	if err := jm.Decode(res.AdmissionStream); err != nil {
		return fmt.Errorf(
			"failed to decode join message from admission stream: %w", err,
		)
	}

	if err := h.validateJoinMessage(jm); err != nil {
		return err
	}

	// If the join message passed validation, we terminate the protocol here.
	// At this point it is the Node's responsibility
	// to consult the kernel to decide whether we accept this join request.
	// (We do that work in the Node to avoid coupling the protocol handlers
	// with the Node's kernel.)
	res.JoinAddr = jm.Addr
	return nil
}

func (h receiveAdmissionStreamHandler) validateJoinMessage(jm dproto.JoinMessage) error {
	// It's cheaper to validate the timestamp first.
	t, err := jm.ParseTimestamp()
	if err != nil {
		return fmt.Errorf("invalid join message: invalid timestamp: %w", err)
	}

	now := h.Cfg.Now() // Prefer a single syscall for current time.
	if now.Before(t.Add(-h.Cfg.GraceBeforeJoinTimestamp)) {
		return fmt.Errorf("invalid join message: timestamp %s too far in future", jm.Timestamp)
	}

	if now.After(t.Add(h.Cfg.GraceAfterJoinTimestamp)) {
		return fmt.Errorf("invalid join message: timestamp %s too far in past", jm.Timestamp)
	}

	// TODO: there may still be unresolved certificate issues preventing this from working.
	// Also we need to plumb the peer certificate through.
	if false {
		// The timestamp checked out, so now validate the signature.
		if err := dcrypto.VerifySignatureWithTLSCert(
			jm.AppendSignContent(nil),
			nil, // Was previously: c.qConn.ConnectionState().TLS.PeerCertificates[0],
			jm.Signature,
		); err != nil {
			return fmt.Errorf("invalid join message: bad signature: %w", err)
		}
	}

	return nil
}

func (h receiveAdmissionStreamHandler) Name() string {
	return "Receive Admission Stream"
}
