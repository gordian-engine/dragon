package dk

import (
	"context"
	"fmt"
	"log/slog"

	"dragon.example/dragon/deval"
)

type Kernel struct {
	log *slog.Logger

	JoinRequests       chan JoinRequest
	NewPeeringRequests chan NewPeeringRequest

	pe deval.PeerEvaluator

	// TODO: we won't keep this,
	// but it is a convenient placeholder for test for now.
	activeViewSize      int
	activeViewSizeCheck chan chan int

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

		JoinRequests:       make(chan JoinRequest),
		NewPeeringRequests: make(chan NewPeeringRequest),

		activeViewSizeCheck: make(chan chan int),

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
			k.handleJoinRequest(ctx, req)

		case req := <-k.NewPeeringRequests:
			k.handleNewPeeringRequest(req)

		case ch := <-k.activeViewSizeCheck:
			ch <- k.activeViewSize
		}
	}
}

// handleJoinRequest handles an incoming join request,
// by consulting the PeerEvaluator,
// and then informing the requester whether to disconnect or accept.
func (k *Kernel) handleJoinRequest(ctx context.Context, req JoinRequest) {
	d, err := k.pe.ConsiderJoin(ctx, req.Peer)
	if err != nil {
		// It's fine if this was a context error,
		// as we should catch it on the next iteration of mainLoop.
		k.log.Info(
			"Error while considering join request",
			"err", err,
		)
		d = deval.DisconnectAndIgnoreJoinDecision
	}

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

	// TODO: handle disconnect and forward case, and accept case.

	// Assume the response channel is buffered.
	req.Resp <- JoinResponse{
		Decision: kd,
	}
}

func (k *Kernel) handleNewPeeringRequest(req NewPeeringRequest) {
	// TODO: there is a chance we could turn down the peering,
	// for instance if there were so many in flight that
	// this one no longer met conditions to enter active view.
	//
	// But at this stage, we'll just treat it like an uncondtional add.

	// For now, just for test, we increment the fake active view size.
	// We still need to figure out the internal API
	// for managing active and passive views.
	k.activeViewSize++

	// Assume the response channel is buffered.
	req.Resp <- NewPeeringResponse{}
}

// GetActiveViewSize is a temporary method to shim tests.
func (k *Kernel) GetActiveViewSize() int {
	ch := make(chan int, 1)
	k.activeViewSizeCheck <- ch
	return <-ch
}
