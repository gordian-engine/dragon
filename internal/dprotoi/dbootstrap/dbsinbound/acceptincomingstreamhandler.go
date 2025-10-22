package dbsinbound

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"

	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dprotoi"
)

// acceptIncomingStreamHandler is the first handler on accepting an incoming connection.
// It expects the joining node to open the admission stream.
type acceptIncomingStreamHandler struct {
	OuterLog *slog.Logger
	PeerCert *x509.Certificate
	Cfg      *Config
}

// Handle accepts the bootstrap stream
// (which is eventually promoted to the admission stream),
// and then it expects either a join or neighbor message from the peer.
// The details of that received message, if valid, are set on the Result.
func (h acceptIncomingStreamHandler) Handle(
	ctx context.Context, c dquic.Conn, res *Result,
) (incomingStreamHandler, error) {
	// There is no plain timeout for accepting a stream,
	// so we have to use a context timeout for this.
	acceptCtx, cancel := context.WithTimeout(ctx, h.Cfg.AcceptBootstrapStreamTimeout)
	defer cancel()

	s, err := c.AcceptStream(acceptCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to accept inbound bootstrap stream: %w", err)
	}
	cancel() // Release cancellation resource now since we are done with it.

	var streamHeader [2]byte

	if err := s.SetReadDeadline(h.Cfg.Now().Add(h.Cfg.ReadStreamHeaderTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set stream header read deadline: %w", err)
	}

	if _, err := io.ReadFull(s, streamHeader[:]); err != nil {
		return nil, fmt.Errorf("failed to read stream header: %w", err)
	}

	if streamHeader[0] != dprotoi.CurrentProtocolVersion {
		return nil, fmt.Errorf("received unexpected protocol version %d in stream header", streamHeader[0])
	}

	switch streamHeader[1] {
	case dprotoi.AdmissionStreamType:
		res.AdmissionStream = s
		return receiveAdmissionStreamHandler{
			OuterLog: h.OuterLog,
			PeerCert: h.PeerCert,
			Cfg:      h.Cfg,
		}, nil
	default:
		return nil, fmt.Errorf("unknown stream type %d for new incoming stream", streamHeader[1])
	}
}

func (h acceptIncomingStreamHandler) Name() string {
	return "Accept Incoming Stream"
}
