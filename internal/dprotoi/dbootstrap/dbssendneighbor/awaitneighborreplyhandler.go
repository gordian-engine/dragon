package dbssendneighbor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dprotoi"
)

type awaitNeighborReplyHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h awaitNeighborReplyHandler) Handle(
	ctx context.Context, _ dquic.Conn, res *Result,
) (handler, error) {
	// The admission stream is open and we have to wait for the candidate peer
	// to send a neighbor reply.

	s := res.Admission
	if err := s.SetReadDeadline(h.Cfg.Now().Add(h.Cfg.AwaitNeighborReplyTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline for neighbor reply: %w", err)
	}

	var nm [2]byte
	if _, err := io.ReadFull(s, nm[:]); err != nil {
		return nil, fmt.Errorf("failed to read neighbor reply message: %w", err)
	}

	if nm[0] != byte(dprotoi.NeighborReplyMessageType) {
		return nil, fmt.Errorf("expected neighbor reply type, got %d", nm[0])
	}

	switch nm[1] {
	case 0:
		// Neighbor request was denied.
		// TODO: we should have a particular error type for this.
		return nil, errors.New("neighbor request denied")

	case 1:
		// Accepted.
		// No more work to do now.
		return nil, nil

	default:
		return nil, fmt.Errorf("peer sent bad neighbor reply byte: %d", nm[1])
	}
}

func (h awaitNeighborReplyHandler) Name() string {
	return "Await Neighbor Reply"
}
