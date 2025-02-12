package dk

import (
	"context"
	"fmt"
	"log/slog"

	"dragon.example/dragon/deval"
)

type Kernel struct {
	log *slog.Logger

	JoinRequests chan JoinRequest

	pe deval.PeerEvaluator

	done chan struct{}
}

type KernelConfig struct {
	PeerEvaluator         deval.PeerEvaluator
	TargetActiveViewSize  int
	TargetPassiveViewSize int
}

func NewKernel(ctx context.Context, log *slog.Logger, cfg KernelConfig) *Kernel {
	k := &Kernel{
		log: log,

		JoinRequests: make(chan JoinRequest),

		pe: cfg.PeerEvaluator,

		done: make(chan struct{}),
	}

	go k.mainLoop(ctx)

	return k
}

func (k *Kernel) Wait() {
	<-k.done
}

func (k *Kernel) mainLoop(ctx context.Context) {
	defer close(k.done)

	for {
		select {
		case <-ctx.Done():
			k.log.Info("Stopping due to context cancellation", "cause", context.Cause(ctx))
			return

		case req := <-k.JoinRequests:
			// Assume that the response channel is buffered.

			d := k.pe.ConsiderJoin(ctx, req.Peer)

			var kd JoinDecision
			switch d {
			case deval.DisconnectAndIgnoreJoinDecision, deval.DisconnectAndForwardJoinDecision:
				kd = DisconnectJoinDecision
			case deval.AcceptJoinDecision:
				kd = AcceptJoinDecision
			default:
				panic(fmt.Errorf(
					"BUG: PeerEvaluator.ConsiderJoin returned illegal JoinDecision %d", d,
				))
			}

			// TODO: handle disconnect and forward case, and accept case

			req.Resp <- JoinResponse{
				Decision: kd,
			}
		}
	}
}
