package dk

import (
	"context"
	"log/slog"
)

type Kernel struct {
	log *slog.Logger

	JoinRequests chan JoinRequest

	done chan struct{}
}

type KernelConfig struct {
	TargetActiveViewSize  int
	TargetPassiveViewSize int
}

func NewKernel(ctx context.Context, log *slog.Logger, cfg KernelConfig) *Kernel {
	k := &Kernel{
		log: log,

		JoinRequests: make(chan JoinRequest),

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

			// TODO: actually consider the input before deciding.
			req.Resp <- JoinResponse{
				Decision: DisconnectJoinDecision,
			}
		}
	}
}
