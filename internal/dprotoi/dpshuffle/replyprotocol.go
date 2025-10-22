package dpshuffle

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dprotoi"
)

// ReplyProtocol is the protocol for sending a response
// to an already handled incoming shuffle.
type ReplyProtocol struct {
	Log *slog.Logger

	Cfg ReplyConfig
}

type ReplyConfig struct {
	SendReplyTimeout time.Duration

	NowFn func() time.Time
}

func (c ReplyConfig) Now() time.Time {
	if c.NowFn != nil {
		return c.NowFn()
	}

	return time.Now()
}

func (p *ReplyProtocol) Run(
	ctx context.Context,
	s dquic.Stream,
	msg dprotoi.ShuffleReplyMessage,
) error {
	if err := s.SetWriteDeadline(p.Cfg.Now().Add(p.Cfg.SendReplyTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// TODO: would be nice to have an EncodedSize method
	// on the ShuffleMessage type.
	var buf bytes.Buffer

	if err := msg.EncodeBare(&buf); err != nil {
		return fmt.Errorf("failed to encode shuffle message: %w", err)
	}

	if _, err := buf.WriteTo(s); err != nil {
		// We probably need a way to feed back up the information that
		// this stream is not working as intended.
		return fmt.Errorf("failed to write outbound shuffle to stream: %w", err)
	}

	return nil
}
