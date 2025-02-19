package dk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/dview"
)

type Kernel struct {
	log *slog.Logger

	JoinRequests       chan JoinRequest
	NewPeeringRequests chan NewPeeringRequest

	vm dview.Manager

	activeViewSizeCheck chan chan int

	done chan struct{}
}

type KernelConfig struct {
	ViewManager dview.Manager

	TargetActiveViewSize  int
	TargetPassiveViewSize int
}

func NewKernel(ctx context.Context, log *slog.Logger, cfg KernelConfig) *Kernel {
	k := &Kernel{
		log: log,

		JoinRequests:       make(chan JoinRequest),
		NewPeeringRequests: make(chan NewPeeringRequest),

		activeViewSizeCheck: make(chan chan int),

		vm: cfg.ViewManager,

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
			k.handleNewPeeringRequest(ctx, req)

		case ch := <-k.activeViewSizeCheck:
			ch <- k.vm.NActivePeers()
		}
	}
}

// handleJoinRequest handles an incoming join request,
// by consulting the PeerEvaluator,
// and then informing the requester whether to disconnect or accept.
func (k *Kernel) handleJoinRequest(ctx context.Context, req JoinRequest) {
	d, err := k.vm.ConsiderJoin(ctx, req.Peer)
	if err != nil {
		// It's fine if this was a context error,
		// as we should catch it on the next iteration of mainLoop.
		k.log.Info(
			"Error while considering join request",
			"err", err,
		)
		d = dview.DisconnectAndIgnoreJoinDecision
	}

	var kd JoinDecision
	switch d {
	case dview.DisconnectAndIgnoreJoinDecision, dview.DisconnectAndForwardJoinDecision:
		kd = DisconnectJoinDecision
	case dview.AcceptJoinDecision:
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

func (k *Kernel) handleNewPeeringRequest(ctx context.Context, req NewPeeringRequest) {
	// There is a chance we could turn down the peering,
	// for instance if there were so many in flight that
	// this one no longer met conditions to enter active view.

	evicted, err := k.vm.AddPeering(ctx, dview.ActivePeer{
		TLS: req.QuicConn.ConnectionState().TLS,

		LocalAddr:  req.QuicConn.LocalAddr(),
		RemoteAddr: req.QuicConn.RemoteAddr(),
	})
	if err != nil {
		k.log.Warn(
			"Error attempting to add peering",
			"err", err,
		)

		req.Resp <- NewPeeringResponse{
			RejectReason: "internal error",
		}
		return
	}

	// Otherwise, since adding the peering succeeded,
	// we inform the requester of the success.
	req.Resp <- NewPeeringResponse{}

	// TODO: seems like we should do something with the evicted entry.
	if evicted != nil {
		k.log.Info(
			"Evicted active peer due to active view overflow",
			"peer_addr", evicted.RemoteAddr.String(),
		)
	}
}

// GetActiveViewSize returns the current number of peers in the active view.
func (k *Kernel) GetActiveViewSize() int {
	ch := make(chan int, 1)
	k.activeViewSizeCheck <- ch
	return <-ch
}
