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

	var protoAndStreamType [2]byte
	if _, err := io.ReadFull(s, protoAndStreamType[:]); err != nil {
		return nil, fmt.Errorf("failed to read protocol and stream type: %w", err)
	}

	if protoAndStreamType[0] != dproto.CurrentProtocolVersion {
		return nil, fmt.Errorf("received unexpected protocol version %d", protoAndStreamType[0])
	}

	switch protoAndStreamType[1] {
	case byte(dproto.ShuffleStreamType):
		return shuffleHandler{
			OuterLog: h.OuterLog,
			Cfg:      h.Cfg,
		}, nil
	default:
		return nil, fmt.Errorf("unknown dynamic stream message type %d", protoAndStreamType[1])
	}
}

func (h identifyStreamHandler) Name() string {
	return "Identify Stream"
}
