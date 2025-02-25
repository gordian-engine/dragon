package dbsacceptjoin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type awaitNeighborReplyHandler struct {
	OuterLog *slog.Logger
	Cfg      *Config
}

func (h awaitNeighborReplyHandler) Handle(
	ctx context.Context, _ quic.Connection, s quic.Stream, res *Result,
) (acceptJoinHandler, error) {
	if err := s.SetReadDeadline(h.Cfg.Now().Add(h.Cfg.NeighborReplyTimeout)); err != nil {
		return nil, fmt.Errorf(
			"failed to set read deadline for incoming neighbor reply: %w", err,
		)
	}

	var tv [2]byte // Type and value.
	if _, err := io.ReadFull(s, tv[:]); err != nil {
		return nil, fmt.Errorf("failed to receive neighbor reply message: %w", err)
	}

	if tv[0] != byte(dproto.NeighborReplyMessageType) {
		return nil, fmt.Errorf(
			"expected neighbor reply message type, got %d", tv[0],
		)
	}

	switch tv[1] {
	case 0:
		// Not accepted.
		// Although this is an expected possible outcome,
		// we still return an error here
		// so that the connectoin gets closed higher in the stack.
		return nil, errors.New("received neighbor reply rejecting our request")
	case 1:
		// Accepted.
		// No more work to do now.
		return nil, nil
	default:
		return nil, fmt.Errorf("received invalid neighbor reply byte 0x%x", tv[1])
	}
}

func (h awaitNeighborReplyHandler) Name() string {
	return "Await Neighbor Reply"
}
