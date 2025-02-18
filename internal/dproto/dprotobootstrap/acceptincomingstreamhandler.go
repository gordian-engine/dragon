package dprotobootstrap

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"dragon.example/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

// acceptIncomingStreamHandler is the first handler on accepting an incoming connection.
// It expects the joining node to open the admission stream.
type acceptIncomingStreamHandler struct {
	OuterLog *slog.Logger
	Cfg      *IncomingConfig
}

func (h acceptIncomingStreamHandler) Handle(
	ctx context.Context, c quic.Connection, res *IncomingResult,
) (incomingStreamHandler, error) {
	// There is no plain timeout for accepting a stream,
	// so we have to use a context timeout for this.
	acceptCtx, cancel := context.WithTimeout(ctx, h.Cfg.AcceptBootstrapStreamTimeout)
	defer cancel()

	s, err := c.AcceptStream(acceptCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to accept stream: %w", err)
	}
	cancel() // Release cancellation resource now since we are done with it.

	var streamHeader [2]byte

	if err := s.SetReadDeadline(h.Cfg.Now().Add(h.Cfg.ReadStreamHeaderTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set stream header read deadline: %w", err)
	}

	if _, err := io.ReadFull(s, streamHeader[:]); err != nil {
		return nil, fmt.Errorf("failed to read stream header: %w", err)
	}

	if streamHeader[0] != dproto.CurrentProtocolVersion {
		return nil, fmt.Errorf("received unexpected protocol version %d in stream header", streamHeader[0])
	}

	switch streamHeader[1] {
	case dproto.AdmissionStreamType:
		res.AdmissionStream = s
		return receiveAdmissionStreamHandler{
			OuterLog: h.OuterLog,
			Cfg:      h.Cfg,
		}, nil
	default:
		return nil, fmt.Errorf("unknown stream type %d for new incoming stream", streamHeader[1])
	}
}

func (h acceptIncomingStreamHandler) Name() string {
	return "Accept Incoming Stream"
}
