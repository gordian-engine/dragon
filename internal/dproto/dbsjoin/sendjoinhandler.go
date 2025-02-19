package dbsjoin

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dcrypto"
	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type sendJoinHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h sendJoinHandler) Handle(
	ctx context.Context, c quic.Connection, res *Result,
) (streamHandler, error) {
	// We only have a bare connection at this point,
	// so we need to set up the admission stream before anything else.

	jm := dproto.JoinMessage{
		Addr: h.Cfg.AdvertiseAddr,
	}
	jm.SetTimestamp(h.Cfg.Now())

	if err := h.signJoinMessage(&jm); err != nil {
		return nil, fmt.Errorf("failed to sign join message: %w", err)
	}

	msg := jm.OpenStreamAndJoinBytes()

	s, err := c.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}
	res.AdmissionStream = s

	// Set write deadline, so that we don't block for a long time
	// in case writing the stream blocks for whatever reason.
	if err := s.SetWriteDeadline(h.Cfg.NowFn().Add(h.Cfg.OpenStreamTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set stream write deadline: %w", err)
	}

	// Send both the open stream header and the join message.
	if _, err := s.Write(msg); err != nil {
		return nil, fmt.Errorf("failed to write stream header and join message: %w", err)
	}

	// We've sent the join message, so now we have to wait for the neighbor message.
	return awaitNeighborRequestHandler{
		OuterLog: h.OuterLog,
		Cfg:      h.Cfg,
	}, nil
}

// signJoinMessage updates jm to include a signature via h.Cfg.Cert.
func (h sendJoinHandler) signJoinMessage(jm *dproto.JoinMessage) error {
	joinSignContent := jm.AppendSignContent(nil)
	sig, err := dcrypto.SignMessageWithTLSCert(joinSignContent, h.Cfg.Cert)
	if err != nil {
		return fmt.Errorf("failed to sign join message: %w", err)
	}

	jm.Signature = sig
	return nil
}

func (h sendJoinHandler) Name() string {
	return "Send Join"
}
