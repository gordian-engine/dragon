package dps

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/internal/dmsg"
	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/gordian-engine/dragon/internal/dps/dfanout"
	"github.com/quic-go/quic-go"
)

// Active handles the network interactions for an active peer set.
type Active struct {
	log *slog.Logger

	// Wait group for directly owned goroutines.
	// This wait group is directly tied to the lifecycle of this type.
	wg sync.WaitGroup

	// Wait group for peer inbound processors' main loops.
	// The processors are associated with individual peers,
	// which can come and go during the lifecycle of the active peer set.
	processorWG sync.WaitGroup

	// Allow looking up a peer by its CA or its own SPKI.
	// Since an iPeer only contains references,
	// we can deal with the peer by value.
	byCASPKI   map[caSPKI]iPeer
	byLeafSPKI map[leafSPKI]iPeer

	processors map[caSPKI]*peerInboundProcessor

	addRequests    chan addRequest
	removeRequests chan removeRequest

	forwardJoinsToNetwork   chan forwardJoinToNetwork
	forwardJoinsFromNetwork chan<- dmsg.ForwardJoinFromNetwork

	initiatedShuffles chan initiatedShuffle
	shufflesFromPeers chan<- dmsg.ShuffleFromPeer

	// Depending on the particular message
	// and whether it needs to be broadcast to all peers
	// or just a single peer in the active view,
	// the APS will send on either seed or work channels.
	seedChannels dfanout.SeedChannels
	workChannels dfanout.WorkChannels
}

// Type aliases to avoid mistakenly accessing a map incorrectly.
type (
	caSPKI   string
	leafSPKI string
)

type ActiveConfig struct {
	// Number of seed goroutines to run.
	// In this context, a seeder is the buffer between
	// the kernel goroutine (whose contention we want to minimize)
	// and the active peer's inbound processors.
	Seeders int

	// Number of worker goroutines to run.
	// The workers are responsible for taking work from the work queue
	// and sending messages on particular QUIC streams.
	Workers int

	// A forward join was received from the network.
	// The active peer set sends the message on this channel.
	ForwardJoinsFromNetwork chan<- dmsg.ForwardJoinFromNetwork

	// A peer sent a shuffle message.
	// The message needs to go up to the kernel
	// so that the view manager can handle it.
	ShufflesFromPeers chan<- dmsg.ShuffleFromPeer
}

func NewActivePeerSet(ctx context.Context, log *slog.Logger, cfg ActiveConfig) *Active {
	seeders := max(2, cfg.Seeders)
	workers := max(4, cfg.Workers)

	a := &Active{
		log: log,

		// Not trying to pre-size these, for now at least.
		byCASPKI:   map[caSPKI]iPeer{},
		byLeafSPKI: map[leafSPKI]iPeer{},

		processors: map[caSPKI]*peerInboundProcessor{},

		// Unbuffered because the caller blocks on these requests anyway.
		addRequests:    make(chan addRequest),
		removeRequests: make(chan removeRequest),

		// We don't want these to block.
		// Unless otherwise noted, these are sized with arbitrary guesses.
		forwardJoinsToNetwork: make(chan forwardJoinToNetwork, 8),
		initiatedShuffles:     make(chan initiatedShuffle, 4),

		// Channels that flow back upward to the kernel.
		forwardJoinsFromNetwork: cfg.ForwardJoinsFromNetwork,
		shufflesFromPeers:       cfg.ShufflesFromPeers,

		seedChannels: dfanout.NewSeedChannels(2 * seeders),
		workChannels: dfanout.NewWorkChannels(2 * workers),
	}

	a.wg.Add(1)
	go a.mainLoop(ctx)

	a.wg.Add(seeders + workers)

	for i := range seeders {
		go dfanout.RunSeeder(
			ctx,
			log.With("seeder_idx", i),
			&a.wg,
			a.seedChannels,
			a.workChannels,
		)
	}

	for i := range workers {
		go dfanout.RunWorker(
			ctx,
			log.With("worker_idx", i),
			&a.wg,
			a.workChannels,
		)
	}

	return a
}

func (a *Active) Wait() {
	a.processorWG.Wait()
	a.wg.Wait()
}

func (a *Active) mainLoop(ctx context.Context) {
	defer a.wg.Done()

	for {
		select {
		case <-ctx.Done():
			a.log.Info("Main loop quitting due to context cancellation", "cause", context.Cause(ctx))

			// This is the highest level component where we have
			// references to every peer's QUIC connection.
			// There is probably a better place to do all of this,
			// but for now in tests,
			// this ensures that all wait groups finish correctly.
			for _, p := range a.byCASPKI {
				p.Conn.CloseWithError(1, "TODO: ungraceful shutdown")
			}

			return

		case req := <-a.addRequests:
			a.handleAddRequest(ctx, req)

		case req := <-a.removeRequests:
			a.handleRemoveRequest(req)

		case fj := <-a.forwardJoinsToNetwork:
			a.handleForwardJoinToNetwork(ctx, fj)

		case is := <-a.initiatedShuffles:
			a.handleInitiatedShuffle(ctx, is)
		}
	}
}

// Add adds the given peer to the active set.
// An error is only returned if the given context was canceled
// before the add operation completes.
func (a *Active) Add(ctx context.Context, p Peer) error {
	resp := make(chan struct{})
	req := addRequest{
		IPeer: p.toInternal(),

		Resp: resp,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while making add request: %w", context.Cause(ctx),
		)

	case a.addRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while waiting for add response: %w", context.Cause(ctx),
		)

	case <-resp:
		return nil
	}
}

func (a *Active) handleAddRequest(ctx context.Context, req addRequest) {
	if _, ok := a.byCASPKI[req.IPeer.CASPKI]; ok {
		panic(fmt.Errorf(
			"BUG: attempted to add peer with CA SPKI %q when one already existed",
			req.IPeer.CASPKI,
		))
	}

	a.byCASPKI[req.IPeer.CASPKI] = req.IPeer
	a.byLeafSPKI[req.IPeer.LeafSPKI] = req.IPeer

	a.processorWG.Add(1)
	a.processors[req.IPeer.CASPKI] = newPeerInboundProcessor(
		ctx,
		a.log.With("peer_inbound_processor", req.IPeer.Conn.RemoteAddr().String()),
		req.IPeer.ToPeer(), a,
	)

	close(req.Resp)
}

// Remove removes the peer with the given ID from the active set.
// An error is only returned if the given context was canceled
// before the remove operation completes.
func (a *Active) Remove(ctx context.Context, pid PeerCertID) error {
	resp := make(chan struct{})
	req := removeRequest{
		PCI: pid,

		Resp: resp,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while making remove request: %w", context.Cause(ctx),
		)

	case a.removeRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while waiting for remove response: %w", context.Cause(ctx),
		)

	case <-resp:
		return nil
	}
}

func (a *Active) handleRemoveRequest(req removeRequest) {
	if _, ok := a.byCASPKI[req.PCI.caSPKI]; !ok {
		panic(fmt.Errorf(
			"BUG: attempted to remove peer with CA SPKI %q when none existed",
			req.PCI.caSPKI,
		))
	}

	delete(a.byCASPKI, req.PCI.caSPKI)
	delete(a.byLeafSPKI, req.PCI.leafSPKI)

	// We delete the processor from the map we manage,
	// but we still indirectly ensure the processor finishes its work
	// by waiting on a.processorWG in a.Wait.
	//
	// TODO: we may need some distinct methods beyond just Cancel.
	a.processors[req.PCI.caSPKI].Cancel()
	delete(a.processors, req.PCI.caSPKI)

	close(req.Resp)
}

func (a *Active) ForwardJoinToNetwork(
	ctx context.Context,
	m dproto.ForwardJoinMessage,
	excludeByCA map[string]struct{},
) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while attempting to start forward join work: %w",
			context.Cause(ctx),
		)

	case a.forwardJoinsToNetwork <- forwardJoinToNetwork{
		Msg:     m,
		Exclude: excludeByCA,
	}:
		return nil
	}
}

func (a *Active) handleForwardJoinToNetwork(ctx context.Context, fj forwardJoinToNetwork) {
	streams := make([]quic.Stream, 0, len(a.byCASPKI))
	for spki, p := range a.byCASPKI {
		if _, ok := fj.Exclude[string(spki)]; ok {
			// Don't send it back to the node who sent it to us.
			continue
		}
		if bytes.Equal(p.Chain.Leaf.RawSubjectPublicKeyInfo, fj.Msg.Chain.Leaf.RawSubjectPublicKeyInfo) {
			// Also don't send it to the node who originated it.
			// Note that we are matching the leaf, not the root, for this.
			// This way, it is possible for two peers from the same CA
			// to get a forward join from each other.
			continue
		}
		streams = append(streams, p.Admission)
	}

	select {
	case <-ctx.Done():
		a.log.Info(
			"Context canceled while attempting to seed forward join message",
			"cause", context.Cause(ctx),
		)

	case a.seedChannels.ForwardJoins <- dfanout.SeedForwardJoin{
		Msg:     fj.Msg,
		Streams: streams,
	}:
		// Okay.
	}
}

// InitiateShuffle enqueues a task to send the given shuffle entries
// to the destination peer given by its CA SPKI.
func (a *Active) InitiateShuffle(
	ctx context.Context,
	dstChain dcert.Chain,
	entries map[string]dproto.ShuffleEntry,
) error {
	// The input here is effectively the final message,
	// so we can just enqueue it as a work item.

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while attempting to initiate shuffle: %w",
			context.Cause(ctx),
		)
	case a.initiatedShuffles <- initiatedShuffle{
		DstCASPKI: string(dstChain.Root.RawSubjectPublicKeyInfo),
		Entries:   entries,
	}:
		// Okay.
		return nil
	}
}

func (a *Active) handleInitiatedShuffle(ctx context.Context, is initiatedShuffle) {
	p, ok := a.byCASPKI[caSPKI(is.DstCASPKI)]
	if !ok {
		a.log.Warn(
			"No peer found for shuffle destination",
		)
		return
	}

	os := dfanout.WorkOutboundShuffle{
		Msg: dproto.ShuffleMessage{
			Entries: is.Entries,
		},

		Conn: p.Conn,
	}

	select {
	case <-ctx.Done():
		a.log.Info(
			"Context canceled while attempting to send outbound shuffle work item",
			"cause", context.Cause(ctx),
		)
	case a.workChannels.OutboundShuffles <- os:
		// Okay.
	}
}
