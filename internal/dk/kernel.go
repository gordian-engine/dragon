package dk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dview"
	"github.com/gordian-engine/dragon/internal/dmsg"
	"github.com/gordian-engine/dragon/internal/dpeerset"
	"github.com/gordian-engine/dragon/internal/dprotoi"
)

type Kernel struct {
	log *slog.Logger

	// Channels created in NewKernel and exposed via the [Requests] type.
	joinRequests             chan JoinRequest
	neighborDecisionRequests chan NeighborDecisionRequest
	addActivePeerRequests    chan AddActivePeerRequest

	// Unexported channels passed to the active peer set.
	forwardJoinsFromNetwork chan dmsg.ForwardJoinFromNetwork
	shufflesFromPeers       chan dmsg.ShuffleFromPeer
	shuffleRepliesFromPeers chan dmsg.ShuffleReplyFromPeer

	// Unexported channels for work that has to happen
	// outside the kernel and outside the active peer set.
	neighborRequests chan<- string

	// External signal, passed via KernelConfig,
	// indicating that a shuffle is due.
	shuffleSignal <-chan struct{}

	vm dview.Manager

	av *dpeerset.ActiveView

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

	// Outgoing channel announcing connection changes in the active view.
	// Passed through directly to the active peer set,
	// otherwise unused in the Kernel.
	ConnectionChanges chan<- dconn.Change
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
	fjfns := make(chan dmsg.ForwardJoinFromNetwork, 8)

	// Pretty much the same for shuffles to/from peers.
	sfps := make(chan dmsg.ShuffleFromPeer, 4)
	srfps := make(chan dmsg.ShuffleReplyFromPeer, 4)

	k := &Kernel{
		log: log,

		joinRequests:             make(chan JoinRequest),
		neighborDecisionRequests: make(chan NeighborDecisionRequest),
		addActivePeerRequests:    make(chan AddActivePeerRequest),

		forwardJoinsFromNetwork: fjfns,
		shufflesFromPeers:       sfps,
		shuffleRepliesFromPeers: srfps,

		activeViewSizeCheck: make(chan chan int),

		neighborRequests: cfg.NeighborRequests,

		shuffleSignal: cfg.ShuffleSignal,

		vm: cfg.ViewManager,
		av: dpeerset.NewActiveView(
			ctx,
			log.With("dk_sys", "active_peer_set"),
			dpeerset.ActiveViewConfig{
				ForwardJoinsFromNetwork: fjfns,
				ShufflesFromPeers:       sfps,
				ShuffleRepliesFromPeers: srfps,

				ConnectionChanges: cfg.ConnectionChanges,
			},
		),

		done: make(chan struct{}),
	}

	go k.mainLoop(ctx)

	return k
}

func (k *Kernel) Wait() {
	<-k.done
	k.av.Wait()
}

func (k *Kernel) mainLoop(ctx context.Context) {
	defer close(k.done)

	// Only used in handleForwardJoinFromNetwork,
	// but needs to persist across calls.
	var fjc forwardJoinCache

	for {
		select {
		case <-ctx.Done():
			k.log.Info("Stopping due to context cancellation", "cause", context.Cause(ctx))
			return

		case req := <-k.joinRequests:
			k.handleJoinRequest(ctx, req)

		case req := <-k.neighborDecisionRequests:
			k.handleNeighborDecisionRequest(ctx, req)

		case req := <-k.addActivePeerRequests:
			k.handleAddActivePeerRequest(ctx, req)

		case req := <-k.forwardJoinsFromNetwork:
			k.handleForwardJoinFromNetwork(ctx, req, &fjc)

		case sfp := <-k.shufflesFromPeers:
			k.handleShuffleFromPeer(ctx, sfp)

		case srfp := <-k.shuffleRepliesFromPeers:
			k.handleShuffleReplyFromPeer(ctx, srfp)

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

func (k *Kernel) AddActivePeerRequests() chan<- AddActivePeerRequest {
	return k.addActivePeerRequests
}

func (k *Kernel) JoinRequests() chan<- JoinRequest {
	return k.joinRequests
}

func (k *Kernel) NeighborDecisionRequests() chan<- NeighborDecisionRequest {
	return k.neighborDecisionRequests
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

	msg := dprotoi.ForwardJoinMessage{
		AA:    req.Msg.AA,
		Chain: req.Peer.Chain,

		TTL: 4, // TODO: make this configurable.
	}
	// This is a fire and forget request.
	if err := k.av.ForwardJoinToNetwork(ctx, msg, nil); err != nil {
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

	evicted, err := k.vm.AddActivePeer(ctx, dview.ActivePeer{
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

	// Otherwise, since adding the peer succeeded,
	// we inform the requester of the success
	// (indicated by an empty RejectReason).
	req.Resp <- AddActivePeerResponse{}

	// And then we add it to the managed active peer set.
	if err := k.av.Add(ctx, dpeerset.Peer{
		Conn: req.QuicConn,

		Chain: req.Chain,
		AA:    req.AA,

		Admission: req.AdmissionStream,
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

		if err := k.av.Remove(
			ctx,
			dpeerset.PeerCertIDFromChain(evicted.Chain),
		); err != nil {
			// The only error returned from Remove should be a context error.
			// Not much we can do here but log it.
			k.log.Warn(
				"Failed to remove peer from active set", "err", err,
			)
		}
	}
}

func (k *Kernel) handleForwardJoinFromNetwork(
	ctx context.Context,
	req dmsg.ForwardJoinFromNetwork,
	fjc *forwardJoinCache,
) {
	// If this chain's forward join was recently seen, don't forward it again.
	fjc.Purge()

	m := req.Msg
	if fjc.Has(m.Chain) {
		return
	}

	d, err := k.vm.ConsiderForwardJoin(ctx, m.AA, m.Chain)
	if err != nil {
		k.log.Warn(
			"Received error from view manager when considering forward join",
			"err", err,
		)
		return
	}

	// Arbitrary duration. Could be configurable.
	fjc.Set(m.Chain, 1500*time.Millisecond)

	if d.ContinueForwarding && m.TTL > 1 {
		m.TTL--

		// We currently prevent forwarding to the sender of the message,
		// but we could possibly adjust the cache
		// so that we track which peers have already seen a particular forward join.
		// Unclear at this point if that would be an improvement.
		exclude := map[string]struct{}{
			string(req.ForwarderCert.RawSubjectPublicKeyInfo): {},
		}

		if err := k.av.ForwardJoinToNetwork(ctx, m, exclude); err != nil {
			k.log.Error("Failed to forward join", "err", err)
			// We don't stop here, because even if forwarding fails for some reason,
			// we may still want to make a neighbor request to the other peer.
		}
	}

	if d.MakeNeighborRequest {
		addr := m.AA.Addr
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

// initiateShuffle is triggered by a shuffle signal.
//
// It gets the outbound shuffle data from the view manager
// and passes it to the active peer set,
// so that the data transfer can happen on another goroutine.
func (k *Kernel) initiateShuffle(ctx context.Context) {
	os, err := k.vm.MakeOutboundShuffle(ctx)
	if err != nil {
		k.log.Error("Outbound shuffle failed", "err", err)
		return
	}

	// Convert the dview entries to dprotoi entries.
	// They are functionally equivalent,
	// but we will not cross-contaminate the public API
	// with the internal representation.
	pses := make([]dprotoi.ShuffleEntry, len(os.Entries))
	for i, e := range os.Entries {
		pses[i] = dprotoi.ShuffleEntry{
			AA:    e.AA,
			Chain: e.Chain,
		}
	}

	// TODO: handle case of two entries having the same chain root

	if err := k.av.InitiateShuffle(ctx, os.Dest, pses); err != nil {
		k.log.Error("Failed to initiate shuffle", "err", err)
		return
	}
}

func (k *Kernel) handleShuffleFromPeer(
	ctx context.Context, sfp dmsg.ShuffleFromPeer,
) {
	// Need to translate the dprotoi shuffle entries to dview shuffle entries.
	entries := make([]dview.ShuffleEntry, 0, len(sfp.Msg.Entries))
	for _, e := range sfp.Msg.Entries {
		entries = append(entries, dview.ShuffleEntry{
			AA:    e.AA,
			Chain: e.Chain,
		})
	}

	got, err := k.vm.MakeShuffleResponse(ctx, sfp.Src, entries)
	if err != nil {
		panic(fmt.Errorf(
			"TODO: handle error when making shuffle response: %w", err,
		))
	}

	// Now translate the dview entries back to dprotoi entries again.
	outbound := make([]dprotoi.ShuffleEntry, len(got))
	for i, e := range got {
		outbound[i] = dprotoi.ShuffleEntry{
			AA:    e.AA,
			Chain: e.Chain,
		}
	}

	k.av.SendShuffleReply(ctx, sfp.Stream, outbound)
}

func (k *Kernel) handleShuffleReplyFromPeer(
	ctx context.Context, srfp dmsg.ShuffleReplyFromPeer,
) {
	// Need to translate the dprotoi shuffle entries to dview shuffle entries.
	entries := make([]dview.ShuffleEntry, 0, len(srfp.Msg.Entries))
	for _, e := range srfp.Msg.Entries {
		entries = append(entries, dview.ShuffleEntry{
			AA:    e.AA,
			Chain: e.Chain,
		})
	}

	if err := k.vm.HandleShuffleResponse(ctx, srfp.Src, entries); err != nil {
		panic(fmt.Errorf(
			"TODO: handle error when handling shuffle response: %w", err,
		))
	}
}

// GetActiveViewSize returns the current number of peers in the active view.
func (k *Kernel) GetActiveViewSize() int {
	ch := make(chan int, 1)
	k.activeViewSizeCheck <- ch
	return <-ch
}

// HasConnectionToAddress consults [*dpeerset.ActiveView.HasConnectionToAddress]
// to determine whether there is an existing connection
// matching the given netAddr.
//
// This is exposed on the Kernel so that the [*dragon.Node]
// does not need to be directly aware of the ActiveView.
//
// See the ActiveView method documentation for details on edge cases.
func (k *Kernel) HasConnectionToAddress(
	ctx context.Context,
	netAddr string,
) (has bool, err error) {
	return k.av.HasConnectionToAddress(ctx, netAddr)
}

// HasConnectionToChain consults [*dpeerset.ActiveView.HasConnectionToChain]
// to determine whether there is an existing connection
// matching the given chain.
//
// This is exposed on the Kernel so that the [*dragon.Node]
// does not need to be directly aware of the ActiveView.
//
// See the ActiveView method documentation for details on edge cases.
func (k *Kernel) HasConnectionToChain(
	ctx context.Context,
	chain dcert.Chain,
) (has bool, err error) {
	return k.av.HasConnectionToChain(ctx, chain)
}
