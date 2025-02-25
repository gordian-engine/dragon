package dbssendjoin

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/daddr"
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
		AA: daddr.AddressAttestation{
			Addr:      h.Cfg.AdvertiseAddr,
			Timestamp: h.Cfg.Now(),
		},
	}

	if err := jm.AA.SignWithTLSCert(h.Cfg.Cert); err != nil {
		return nil, fmt.Errorf("failed to sign join message: %w", err)
	}
	res.AA = jm.AA

	msg := jm.OpenStreamAndJoinBytes()

	s, err := c.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}
	res.AdmissionStream = s

	// Set write deadline, so that we don't block for a long time
	// in case writing the stream blocks for whatever reason.
	if err := s.SetWriteDeadline(h.Cfg.Now().Add(h.Cfg.OpenStreamTimeout)); err != nil {
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

func (h sendJoinHandler) Name() string {
	return "Send Join"
}
