package dpshuffle

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dmsg"
	"github.com/gordian-engine/dragon/internal/dprotoi"
)

type InitiateProtocol struct {
	Log *slog.Logger

	Cfg Config
}

type Config struct {
	SendShuffleTimeout  time.Duration
	ReceiveReplyTimeout time.Duration

	ShuffleRepliesFromPeers chan<- dmsg.ShuffleReplyFromPeer

	NowFn func() time.Time
}

func (c Config) Now() time.Time {
	if c.NowFn != nil {
		return c.NowFn()
	}

	return time.Now()
}

func (p *InitiateProtocol) Run(
	ctx context.Context,
	chain dcert.Chain,
	c dquic.Conn,
	msg dprotoi.ShuffleMessage,
) error {
	// Unlike the more complex protocols,
	// this one just opens a stream and sends one message,
	// so we will do all the work inline here.
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer p.closeStream(s)

	if err := s.SetWriteDeadline(p.Cfg.Now().Add(p.Cfg.SendShuffleTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// TODO: would be nice to have an EncodedSize method
	// on the ShuffleMessage type.
	var buf bytes.Buffer
	_ = buf.WriteByte(dprotoi.CurrentProtocolVersion)
	_ = buf.WriteByte(dprotoi.ShuffleStreamType)

	if err := msg.EncodeBare(&buf); err != nil {
		return fmt.Errorf("failed to encode shuffle message: %w", err)
	}

	if _, err := buf.WriteTo(s); err != nil {
		// We probably need a way to feed back up the information that
		// this stream is not working as intended.
		return fmt.Errorf("failed to write outbound shuffle to stream: %w", err)
	}

	// Now read the response back.
	if err := s.SetReadDeadline(p.Cfg.Now().Add(p.Cfg.ReceiveReplyTimeout)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	var shufReply dprotoi.ShuffleReplyMessage
	if err := shufReply.Decode(s); err != nil {
		return fmt.Errorf("failed to decode shuffle reply: %w", err)
	}

	out := dmsg.ShuffleReplyFromPeer{
		Src: chain,
		Msg: shufReply,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while sending shuffle reply back to kernel: %w",
			context.Cause(ctx),
		)

	case p.Cfg.ShuffleRepliesFromPeers <- out:
		// Okay.
		return nil
	}
}

func (p *InitiateProtocol) closeStream(s dquic.Stream) {
	if err := s.Close(); err != nil {
		p.Log.Info(
			"Error when closing ephemeral stream for shuffles",
			"err", err,
		)
	}
}
