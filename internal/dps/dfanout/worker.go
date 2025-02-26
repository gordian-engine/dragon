package dfanout

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/internal/dproto/dpshuffle"
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
			handleWorkOutboundShuffle(ctx, log, os)
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

func handleWorkOutboundShuffle(ctx context.Context, log *slog.Logger, os WorkOutboundShuffle) {
	p := dpshuffle.Protocol{
		Log: log,
		Cfg: dpshuffle.Config{
			SendShuffleTimeout: 50 * time.Millisecond,
		},
	}

	s, err := p.Run(ctx, os.Conn, os.Msg)
	if err != nil {
		panic(fmt.Errorf("TODO: handle error running shuffle protocol: %w", err))
	}

	// TODO: we need to read the response on s.
	_ = s
}
