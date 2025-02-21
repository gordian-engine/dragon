package dk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gordian-engine/dragon/dview"
	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/gordian-engine/dragon/internal/dps"
)

type Kernel struct {
	log *slog.Logger

	// Exported channels exposed directly to the owning Node.
	JoinRequests       chan JoinRequest
	NewPeeringRequests chan NewPeeringRequest

	// Unexported channels passed to the active peer set.
	forwardJoinsFromNetwork chan dps.ForwardJoinFromNetwork

	// Unexported channels for work that has to happen
	// outside the kernel and outside the active peer set.
	neighborRequests chan<- string

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
}

func NewKernel(ctx context.Context, log *slog.Logger, cfg KernelConfig) *Kernel {
	// We don't want to have workers blocked on sending messages
	// back upwards toward the kernel.
	// Plus, it's fine if these messages aren't handled instantly.
	// These are all arbitrarily sized.
	fjfns := make(chan dps.ForwardJoinFromNetwork, 8)

	k := &Kernel{
		log: log,

		JoinRequests:       make(chan JoinRequest),
		NewPeeringRequests: make(chan NewPeeringRequest),

		forwardJoinsFromNetwork: fjfns,

		activeViewSizeCheck: make(chan chan int),

		neighborRequests: cfg.NeighborRequests,

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

		case req := <-k.NewPeeringRequests:
			k.handleNewPeeringRequest(ctx, req)

		case req := <-k.forwardJoinsFromNetwork:
			k.handleForwardJoinFromNetwork(ctx, req)

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
		JoinMessage:      req.Msg,
		JoiningCertChain: req.Peer.TLS.VerifiedChains[0],

		TTL: 4, // TODO: make this configurable.
	}
	// This is a fire and forget request.
	if err := k.aps.ForwardJoinToNetwork(ctx, msg, nil); err != nil {
		k.log.Error("Failed to forward join", "err", err)
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

	// And then we add it to the managed active peer set.
	if err := k.aps.Add(ctx, dps.Peer{
		Conn: req.QuicConn,

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
			dps.PeerCertIDFromCerts(evicted.TLS.PeerCertificates), // TODO: shouldn't this be VerifiedCertificates?
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
	d, err := k.vm.ConsiderForwardJoin(ctx, req.Msg)
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
		addr := req.Msg.JoinMessage.Addr
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

// GetActiveViewSize returns the current number of peers in the active view.
func (k *Kernel) GetActiveViewSize() int {
	ch := make(chan int, 1)
	k.activeViewSizeCheck <- ch
	return <-ch
}
