package dfanout

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/internal/dproto"
)

func RunWorker(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	work WorkChannels,
) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			log.Info(
				"Worker stopping due to context cancellation",
				"cause", context.Cause(ctx),
			)
			return

		case fj := <-work.ForwardJoins:
			handleWorkForwardJoin(fj)

		case os := <-work.OutboundShuffles:
			handleWorkOutboundShuffle(ctx, os)
		}
	}
}

func handleWorkForwardJoin(fj WorkForwardJoin) {
	// TODO: make time.Now a parameter intead of hardcoding it?
	if err := fj.Stream.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		panic(fmt.Errorf(
			"TODO: handle error setting write deadline for forward join: %w",
			err,
		))
	}
	if _, err := fj.Stream.Write(fj.Raw); err != nil {
		// We probably need a way to feed back up the information that
		// this stream is not working as intended.
		panic(fmt.Errorf(
			"TODO: handle error when writing forward join to stream: %w",
			err,
		))
	}
}

func handleWorkOutboundShuffle(ctx context.Context, os WorkOutboundShuffle) {
	// Make an ephemeral stream for this outbound shuffle.
	s, err := os.Conn.OpenStreamSync(ctx)
	if err != nil {
		panic(fmt.Errorf(
			"TODO: handle error opening shuffle stream: %w", err,
		))
	}

	// TODO: seems like this should delegate to a Protocol too.

	// TODO: make time.Now a parameter intead of hardcoding it?
	if err := s.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		panic(fmt.Errorf(
			"TODO: handle error setting write deadline for outbound shuffle: %w",
			err,
		))
	}

	// TODO: would be nice to have an EncodedSize method
	// on the ShuffleMessage type.
	var buf bytes.Buffer
	_ = buf.WriteByte(dproto.CurrentProtocolVersion)
	_ = buf.WriteByte(dproto.ShuffleStreamType)

	if err := os.Msg.EncodeBare(&buf); err != nil {
		panic(fmt.Errorf(
			"TODO: handle error encoding shuffle message: %w", err,
		))
	}

	if _, err := buf.WriteTo(s); err != nil {
		// We probably need a way to feed back up the information that
		// this stream is not working as intended.
		panic(fmt.Errorf(
			"TODO: handle error when writing outbound shuffle to stream: %w",
			err,
		))
	}
}
