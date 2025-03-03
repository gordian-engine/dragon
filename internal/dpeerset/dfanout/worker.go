package dfanout

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/internal/dmsg"
	"github.com/gordian-engine/dragon/internal/dprotoi/dpshuffle"
)

func RunWorker(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	work WorkChannels,
	out WorkerOutputChannels,
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
			handleWorkOutboundShuffle(ctx, log, os, out.ShuffleRepliesFromPeers)

		case osr := <-work.OutboundShuffleReplies:
			handleWorkOutboundShuffleReply(
				ctx, log, osr,
			)
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

func handleWorkOutboundShuffle(
	ctx context.Context,
	log *slog.Logger,
	os WorkOutboundShuffle,
	replyCh chan<- dmsg.ShuffleReplyFromPeer,
) {
	shuf := dpshuffle.InitiateProtocol{
		Log: log,
		Cfg: dpshuffle.Config{
			SendShuffleTimeout:  50 * time.Millisecond,
			ReceiveReplyTimeout: 75 * time.Millisecond,

			ShuffleRepliesFromPeers: replyCh,
		},
	}

	if err := shuf.Run(ctx, os.Chain, os.Conn, os.Msg); err != nil {
		panic(fmt.Errorf("TODO: handle error running shuffle protocol: %w", err))
	}
}

func handleWorkOutboundShuffleReply(
	ctx context.Context,
	log *slog.Logger,
	osr WorkOutboundShuffleReply,
) {
	defer func() {
		if err := osr.Stream.Close(); err != nil {
			log.Info("Error closing shuffle stream", "err", err)
		}
	}()

	shuf := dpshuffle.ReplyProtocol{
		Log: log,
		Cfg: dpshuffle.ReplyConfig{
			SendReplyTimeout: 50 * time.Millisecond,
		},
	}

	if err := shuf.Run(ctx, osr.Stream, osr.Msg); err != nil {
		panic(fmt.Errorf("TODO: handle error running shuffle reply protocol: %w", err))
	}
}
