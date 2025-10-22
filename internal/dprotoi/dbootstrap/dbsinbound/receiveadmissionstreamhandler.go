package dbsinbound

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"

	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dprotoi"
)

// receiveAdmisisonStreamHandler handles receiving initial data
// on a newly opened admission stream.
type receiveAdmissionStreamHandler struct {
	OuterLog *slog.Logger
	PeerCert *x509.Certificate
	Cfg      *Config
}

func (h receiveAdmissionStreamHandler) Handle(
	ctx context.Context, c dquic.Conn, res *Result,
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
	case byte(dprotoi.JoinMessageType):
		// Returned error will be wrapped properly.
		return nil, h.handleJoinMessage(res)

	case byte(dprotoi.NeighborMessageType):
		return nil, h.handleNeighborMessage(res)

	default:
		return nil, fmt.Errorf("invalid admission stream message type: %d", typeBuf[0])
	}
}

func (h receiveAdmissionStreamHandler) handleJoinMessage(
	res *Result,
) error {
	// Still relying on the earlier set read deadline.
	var jm dprotoi.JoinMessage
	if err := jm.Decode(res.AdmissionStream); err != nil {
		return fmt.Errorf(
			"failed to decode join message from admission stream: %w", err,
		)
	}

	if err := h.validateAddressAttestation(jm.AA); err != nil {
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

func (h receiveAdmissionStreamHandler) handleNeighborMessage(
	res *Result,
) error {
	// Still relying on the earlier set read deadline.
	var nm dprotoi.NeighborMessage
	if err := nm.Decode(res.AdmissionStream); err != nil {
		return fmt.Errorf(
			"failed to decode join message from admission stream: %w", err,
		)
	}

	if err := h.validateAddressAttestation(nm.AA); err != nil {
		return err
	}

	// If the neighbor message passed validation, we terminate the protocol here.
	// At this point it is the Node's responsibility
	// to consult the kernel to decide whether we accept this neighbor request.
	// (We do that work in the Node to avoid coupling the protocol handlers
	// with the Node's kernel.)
	res.NeighborMessage = &nm
	return nil
}

func (h receiveAdmissionStreamHandler) validateAddressAttestation(
	aa daddr.AddressAttestation,
) error {
	// It's cheaper to validate the timestamp first.
	now := h.Cfg.Now() // Prefer a single syscall for current time.
	ts := aa.Timestamp
	if now.Before(ts.Add(-h.Cfg.GraceBeforeJoinTimestamp)) {
		return fmt.Errorf("invalid join message: timestamp %s too far in future", ts)
	}

	if now.After(ts.Add(h.Cfg.GraceAfterJoinTimestamp)) {
		return fmt.Errorf("invalid join message: timestamp %s too far in past", ts)
	}

	// The timestamp checked out, so now validate the signature.
	if err := aa.VerifySignature(h.PeerCert); err != nil {
		return fmt.Errorf("invalid join message: bad signature: %w", err)
	}

	return nil
}

func (h receiveAdmissionStreamHandler) Name() string {
	return "Receive Admission Stream"
}
