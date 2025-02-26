package dpshuffle

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

type Protocol struct {
	Log *slog.Logger

	Cfg Config
}

type Config struct {
	SendShuffleTimeout time.Duration

	NowFn func() time.Time
}

func (c Config) Now() time.Time {
	if c.NowFn != nil {
		return c.NowFn()
	}

	return time.Now()
}

func (p *Protocol) Run(
	ctx context.Context, c quic.Connection, msg dproto.ShuffleMessage,
) (quic.Stream, error) {
	// Unlike the more complex protocols,
	// this one just opens a stream and sends one message,
	// so we will do all the work inline here.
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	if err := s.SetWriteDeadline(p.Cfg.Now().Add(p.Cfg.SendShuffleTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set write deadline: %w", err)
	}

	// TODO: would be nice to have an EncodedSize method
	// on the ShuffleMessage type.
	var buf bytes.Buffer
	_ = buf.WriteByte(dproto.CurrentProtocolVersion)
	_ = buf.WriteByte(dproto.ShuffleStreamType)

	if err := msg.EncodeBare(&buf); err != nil {
		return nil, fmt.Errorf("failed to encode shuffle message: %w", err)
	}

	if _, err := buf.WriteTo(s); err != nil {
		// We probably need a way to feed back up the information that
		// this stream is not working as intended.
		return nil, fmt.Errorf("failed to write outbound shuffle to stream: %w", err)
	}

	return s, nil
}
