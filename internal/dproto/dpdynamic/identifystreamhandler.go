package dpdynamic

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type identifyStreamHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h identifyStreamHandler) Handle(
	ctx context.Context, s quic.Stream, res *Result,
) (handler, error) {
	if err := s.SetReadDeadline(h.Cfg.Now().Add(h.Cfg.IdentifyStreamTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline on dynamic stream: %w", err)
	}

	// Normally we would read the protocol and stream byte together.
	// But on this dynamic type,
	// we don't know if it is protocol or application
	// without reading the first byte,
	// and it's a pain to re-buffer an already read byte.

	var single [1]byte
	if _, err := io.ReadFull(s, single[:]); err != nil {
		return nil, fmt.Errorf("failed to read protocol type: %w", err)
	}

	if single[0] >= 128 { // TODO: this should be a constant somewhere.
		res.ApplicationProtocolID = single[0]
		return nil, nil
	}

	if single[0] != dproto.CurrentProtocolVersion {
		return nil, fmt.Errorf("received unexpected protocol version %d", single[0])
	}

	if _, err := io.ReadFull(s, single[:]); err != nil {
		return nil, fmt.Errorf("failed to read stream type: %w", err)
	}

	switch single[0] {
	case byte(dproto.ShuffleStreamType):
		return shuffleHandler{
			OuterLog: h.OuterLog,
			Cfg:      h.Cfg,
		}, nil
	default:
		return nil, fmt.Errorf("unknown dynamic stream message type %d", single[0])
	}
}

func (h identifyStreamHandler) Name() string {
	return "Identify Stream"
}
