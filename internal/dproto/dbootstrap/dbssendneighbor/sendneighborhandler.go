package dbssendneighbor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dcrypto"
	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type sendNeighborHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h sendNeighborHandler) Handle(
	ctx context.Context, c quic.Connection, res *Result,
) (handler, error) {
	// We only have a bare connection at this point,
	// so we need to set up the admission stream before anything else.

	aa := dproto.AddressAttestation{
		Addr:      h.Cfg.AdvertiseAddr,
		Timestamp: h.Cfg.Now(),
	}

	joinSignContent := aa.AppendSignContent(nil)
	sig, err := dcrypto.SignMessageWithTLSCert(joinSignContent, h.Cfg.Cert)
	if err != nil {
		return nil, fmt.Errorf("failed to sign address attestation: %w", err)
	}

	aa.Signature = sig

	// There's no apparent other way to set a deadline on opening a stream,
	// besides using OpenStreamSync with a cancelable context.
	deadline := h.Cfg.Now().Add(h.Cfg.OpenStreamTimeout)
	openCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	s, err := c.OpenStreamSync(openCtx)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to open stream to bootstrap neighbor: %w", err,
		)
	}
	cancel() // Release resources as early as possible.

	// There is no content in the neighbor message,
	// so we can just open the stream and send the message ID.
	if err := s.SetWriteDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set neighbor bootstrap stream deadline: %w", err)
	}

	buf := bytes.NewBuffer(make([]byte, 0, 3+aa.EncodedSize()))
	_ = buf.WriteByte(dproto.CurrentProtocolVersion)
	_ = buf.WriteByte(byte(dproto.AdmissionStreamType))
	_ = buf.WriteByte(byte(dproto.NeighborMessageType))

	if err := aa.Encode(buf); err != nil {
		panic(errors.New(
			"BUG: encoding an address attestation should never fail",
		))
	}
	if _, err := buf.WriteTo(s); err != nil {
		return nil, fmt.Errorf("failed to write stream header and neighbor message type: %w", err)
	}

	res.Admission = s

	// We've sent the message, now we wait for the peer's reply.
	return awaitNeighborReplyHandler{
		OuterLog: h.OuterLog,
		Cfg:      h.Cfg,
	}, nil
}

func (h sendNeighborHandler) Name() string {
	return "Send Neighbor Bootstrap"
}
