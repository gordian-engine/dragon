package dbssendneighbor

import (
	"context"
	"fmt"
	"log/slog"

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

	out := [3]byte{
		dproto.CurrentProtocolVersion,
		byte(dproto.AdmissionStreamType),
		byte(dproto.NeighborMessageType),
	}
	if _, err := s.Write(out[:]); err != nil {
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
