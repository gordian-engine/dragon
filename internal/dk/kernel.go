package dk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/dview"
	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/gordian-engine/dragon/internal/dps"
)

type Kernel struct {
	log *slog.Logger

	// Exported channels exposed directly to the owning Node.

	// Sender needs a decision about what to do with
	// a Join message received from an unknown peer.
	JoinRequests chan JoinRequest

	// Sender needs a decision about what to do with
	// a Neighbor message received from an unknown peer.
	NeighborDecisionRequests chan NeighborDecisionRequest

	// Sender has a completely bootstrapped connection
	// and wants to add it to the active set.
	AddActivePeerRequests chan AddActivePeerRequest

	// Unexported channels passed to the active peer set.
	forwardJoinsFromNetwork chan dps.ForwardJoinFromNetwork

	// Unexported channels for work that has to happen
	// outside the kernel and outside the active peer set.
	neighborRequests chan<- string

	// External signal, passed via KernelConfig,
	// indicating that a shuffle is due.
	shuffleSignal <-chan struct{}

	vm dview.Manager

	aps *dps.Active // Active Peer Set.

	activeViewSizeCheck chan chan int

	done chan struct{}
}

type KernelConfig struct {
	ViewManager dview.Manager

	TargetActiveViewSize  int
	TargetPassiveViewSize int

	// When the kernel's ViewManager decides to make a neighbor request
	// to a peer, that work must happen outside the kernel to reduce contention.
	//
	// Peer addresses are sent on this channel to initiate neighbor requests,
	// and if the connection succeeds,
	// it will eventually feed back into the Kernel
	// through the NewPeeringRequests channel.
	NeighborRequests chan<- string

	// A value sent on this channel indicates that a shuffle is due.
	ShuffleSignal <-chan struct{}
}

func NewKernel(ctx context.Context, log *slog.Logger, cfg KernelConfig) *Kernel {
	// The entire channel for forward joins from network
	// is scoped within the kernel.
	// The kernel receives from it and the active peer set sends to it.
	//
	// We don't want to have workers blocked on sending messages
	// back upwards toward the kernel.
	// Plus, it's fine if these messages aren't handled instantly.
	// The channel size is an arbitrary guess right now.
	fjfns := make(chan dps.ForwardJoinFromNetwork, 8)

	k := &Kernel{
		log: log,

		JoinRequests:             make(chan JoinRequest),
		NeighborDecisionRequests: make(chan NeighborDecisionRequest),
		AddActivePeerRequests:    make(chan AddActivePeerRequest),

		forwardJoinsFromNetwork: fjfns,

		activeViewSizeCheck: make(chan chan int),

		neighborRequests: cfg.NeighborRequests,

		shuffleSignal: cfg.ShuffleSignal,

		vm: cfg.ViewManager,
		aps: dps.NewActivePeerSet(
			ctx,
			log.With("dk_sys", "active_peer_set"),
			dps.ActiveConfig{
				ForwardJoinsFromNetwork: fjfns,
			},
		),

		done: make(chan struct{}),
	}

	go k.mainLoop(ctx)

	return k
}

func (k *Kernel) Wait() {
	<-k.done
	k.aps.Wait()
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

		case req := <-k.NeighborDecisionRequests:
			k.handleNeighborDecisionRequest(ctx, req)

		case req := <-k.AddActivePeerRequests:
			k.handleAddActivePeerRequest(ctx, req)

		case req := <-k.forwardJoinsFromNetwork:
			k.handleForwardJoinFromNetwork(ctx, req)

		case _, ok := <-k.shuffleSignal:
			if !ok {
				panic(errors.New(
					"BUG: misuse of ShuffleSignal: channel must not be closed",
				))
			}

			k.initiateShuffle(ctx)

		case ch := <-k.activeViewSizeCheck:
			// Assuming the incoming request is buffered.
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

	// Assume the response channel is buffered.
	req.Resp <- JoinResponse{
		Decision: kd,
	}

	if d == dview.DisconnectAndIgnoreJoinDecision {
		return
	}

	// We need to forward the join
	// (whether we accepted or disconnected at this point),
	// so we delegate this to the active peer set.

	msg := dproto.ForwardJoinMessage{
		AA:    req.Msg.AA,
		Chain: req.Peer.Chain,

		TTL: 4, // TODO: make this configurable.
	}
	// This is a fire and forget request.
	if err := k.aps.ForwardJoinToNetwork(ctx, msg, nil); err != nil {
		k.log.Error("Failed to forward join", "err", err)
	}
}

func (k *Kernel) handleNeighborDecisionRequest(ctx context.Context, req NeighborDecisionRequest) {
	accept, err := k.vm.ConsiderNeighborRequest(ctx, req.Peer)
	if err != nil {
		// It's fine if this was a context error,
		// as we should catch it on the next iteration of mainLoop.
		k.log.Info(
			"Error while considering neighbor request",
			"err", err,
		)
		accept = false
	}

	// Assume the response channel is buffered.
	req.Resp <- accept
}

func (k *Kernel) handleAddActivePeerRequest(ctx context.Context, req AddActivePeerRequest) {
	// There is a chance we could turn down the peering,
	// for instance if there were so many in flight that
	// this one no longer met conditions to enter active view.

	evicted, err := k.vm.AddPeering(ctx, dview.ActivePeer{
		Chain: req.Chain,
		AA:    req.AA,

		LocalAddr:  req.QuicConn.LocalAddr(),
		RemoteAddr: req.QuicConn.RemoteAddr(),
	})
	if err != nil {
		k.log.Warn(
			"Error attempting to add active peer",
			"err", err,
		)

		req.Resp <- AddActivePeerResponse{
			RejectReason: "internal error",
		}
		return
	}

	// Otherwise, since adding the peering succeeded,
	// we inform the requester of the success.
	req.Resp <- AddActivePeerResponse{}

	// And then we add it to the managed active peer set.
	if err := k.aps.Add(ctx, dps.Peer{
		Conn: req.QuicConn,

		Chain: req.Chain,
		AA:    req.AA,

		Admission:  req.AdmissionStream,
		Disconnect: req.DisconnectStream,
		Shuffle:    req.ShuffleStream,
	}); err != nil {
		// This currently can only be a context error,
		// so it is terminal.
		k.log.Warn(
			"Failed to add new peer to managed active peer set",
			"err", err,
		)
		return
	}

	if evicted != nil {
		k.log.Info(
			"Evicted active peer due to active view overflow",
			"peer_addr", evicted.RemoteAddr.String(),
		)

		if err := k.aps.Remove(
			ctx,
			dps.PeerCertIDFromChain(evicted.Chain),
		); err != nil {
			// The only error returned from Remove should be a context error.
			// Not much we can do here but log it.
			k.log.Warn(
				"Failed to remove peer from active set", "err", err,
			)
		}
	}
}

func (k *Kernel) handleForwardJoinFromNetwork(ctx context.Context, req dps.ForwardJoinFromNetwork) {
	fjm := req.Msg
	d, err := k.vm.ConsiderForwardJoin(ctx, fjm.AA, fjm.Chain)
	if err != nil {
		k.log.Warn(
			"Received error from view manager when considering forward join",
			"err", err,
		)
		return
	}

	if d.ContinueForwarding && req.Msg.TTL > 1 {
		req.Msg.TTL--

		// TODO: we should have some kind of TTL cache
		// so that we exclude cycles if we have received this message from multiple peers.
		exclude := map[string]struct{}{
			string(req.ForwarderCert.RawSubjectPublicKeyInfo): {},
		}

		if err := k.aps.ForwardJoinToNetwork(ctx, req.Msg, exclude); err != nil {
			k.log.Error("Failed to forward join", "err", err)
			// We don't stop here, because even if forwarding fails for some reason,
			// we may still want to make a neighbor request to the other peer.
		}
	}

	if d.MakeNeighborRequest {
		addr := fjm.AA.Addr
		select {
		case k.neighborRequests <- addr:
			// Okay.
		default:
			k.log.Warn(
				"Dropped neighbor request due to backpressure",
				"addr", addr,
			)
		}
	}
}

func (k *Kernel) initiateShuffle(ctx context.Context) {
	// TODO: finish implementing this.

	os, err := k.vm.MakeOutboundShuffle(ctx)
	if err != nil {
		k.log.Error("Outbound shuffle failed", "err", err)
		return
	}
	_ = os

	if err := k.aps.InitiateShuffle(ctx); err != nil {
		k.log.Error("Failed to initiate shuffle", "err", err)
		return
	}
}

// GetActiveViewSize returns the current number of peers in the active view.
func (k *Kernel) GetActiveViewSize() int {
	ch := make(chan int, 1)
	k.activeViewSizeCheck <- ch
	return <-ch
}
