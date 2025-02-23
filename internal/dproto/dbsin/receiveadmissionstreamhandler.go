package dbsin

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

// receiveAdmisisonStreamHandler handles receiving initial data
// on a newly opened admission stream.
type receiveAdmissionStreamHandler struct {
	OuterLog *slog.Logger
	PeerCert *x509.Certificate
	Cfg      *Config
}

func (h receiveAdmissionStreamHandler) Handle(
	ctx context.Context, c quic.Connection, res *Result,
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

	case byte(dproto.NeighborMessageType):
		// There is no data inside the neighbor message,
		// so we don't have to read anything.
		// We just have to mark the Result.
		res.NeighborMessage = true
		return nil, nil

	default:
		return nil, fmt.Errorf("invalid admission stream message type: %d", typeBuf[0])
	}
}

func (h receiveAdmissionStreamHandler) handleJoinMessage(
	res *Result,
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
	res.JoinMessage = &jm
	return nil
}

func (h receiveAdmissionStreamHandler) validateJoinMessage(jm dproto.JoinMessage) error {
	// It's cheaper to validate the timestamp first.
	now := h.Cfg.Now() // Prefer a single syscall for current time.
	ts := jm.AA.Timestamp
	if now.Before(ts.Add(-h.Cfg.GraceBeforeJoinTimestamp)) {
		return fmt.Errorf("invalid join message: timestamp %s too far in future", ts)
	}

	if now.After(ts.Add(h.Cfg.GraceAfterJoinTimestamp)) {
		return fmt.Errorf("invalid join message: timestamp %s too far in past", ts)
	}

	// The timestamp checked out, so now validate the signature.
	if err := jm.AA.VerifySignature(h.PeerCert); err != nil {
		return fmt.Errorf("invalid join message: bad signature: %w", err)
	}

	return nil
}

func (h receiveAdmissionStreamHandler) Name() string {
	return "Receive Admission Stream"
}
