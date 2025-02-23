package dfanout

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
)

func RunSeeder(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	seed SeedChannels,
	work WorkChannels,
) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			log.Info(
				"Seeder stopping due to context cancellation",
				"cause", context.Cause(ctx),
			)
			return

		case sfj := <-seed.ForwardJoins:
			handleSeedForwardJoin(ctx, log, sfj, work.ForwardJoins)
		}
	}
}

func handleSeedForwardJoin(
	ctx context.Context,
	log *slog.Logger,
	sfj SeedForwardJoin,
	out chan<- WorkForwardJoin,
) {
	// TODO: possible allocation improvement to reuse this buffer.
	// But we might not see forward joins enough to be worth the trouble.
	var buf bytes.Buffer

	if err := sfj.Msg.Encode(&buf); err != nil {
		log.Error("Failed to encode forward join message", "err", err)
		return
	}

	raw := buf.Bytes()

	for _, s := range sfj.Streams {
		w := WorkForwardJoin{
			Raw:    raw,
			Stream: s,
		}

		select {
		case <-ctx.Done():
			log.Warn(
				"Context canceled while sending forward join work",
				"cause", context.Cause(ctx),
			)
			return
		case out <- w:
			// Okay.
		}
	}
}
