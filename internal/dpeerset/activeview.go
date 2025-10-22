package dpeerset

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dmsg"
	"github.com/gordian-engine/dragon/internal/dpeerset/dfanout"
	"github.com/gordian-engine/dragon/internal/dprotoi"
	"github.com/gordian-engine/dragon/internal/dquicwrap"
)

// ActiveView handles the network interactions for an active peer set.
//
// The [dview.Manager] determines when to call
// [*ActiveView.Add] and [*ActiveView.Remove];
// the [*dk.Kernel] coordinates the two types.
type ActiveView struct {
	log *slog.Logger

	// Wait group for directly owned goroutines.
	// This wait group is directly tied to the lifecycle of this type.
	wg sync.WaitGroup

	// Wait group for peer inbound processors' main loops.
	// The processors are associated with individual peers,
	// which can come and go during the lifecycle of the active peer set.
	processorWG sync.WaitGroup

	// Allow looking up a peer by its CA or its own leaf certificate.
	// Since an iPeer only contains references,
	// we can deal with the peer by value.
	byCA   map[dcert.CACertHandle]iPeer
	byLeaf map[dcert.LeafCertHandle]iPeer

	// Track the dconn.Conn values we send through the connectionChanges channel,
	// so that we can send proper remove messages.
	dconnByLeafCert map[dcert.LeafCertHandle]dconn.Conn

	processors map[dcert.CACertHandle]*peerInboundProcessor

	addRequests    chan addRequest
	removeRequests chan removeRequest

	checkConnAddrRequests  chan checkConnAddrRequest
	checkConnChainRequests chan checkConnChainRequest

	forwardJoinsToNetwork   chan forwardJoinToNetwork
	forwardJoinsFromNetwork chan<- dmsg.ForwardJoinFromNetwork

	initiatedShuffles       chan initiatedShuffle
	shufflesFromPeers       chan<- dmsg.ShuffleFromPeer
	shuffleRepliesFromPeers chan<- dmsg.ShuffleReplyFromPeer

	connectionChanges chan<- dconn.Change

	// Depending on the particular message
	// and whether it needs to be broadcast to all peers
	// or just a single peer in the active view,
	// the APS will send on either seed or work channels.
	seedChannels dfanout.SeedChannels
	workChannels dfanout.WorkChannels
}

type ActiveViewConfig struct {
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

	// A peer replied to our outgoing shuffle message.
	// We need to pass it through the kernel to the view manager.
	ShuffleRepliesFromPeers chan<- dmsg.ShuffleReplyFromPeer

	// When a peer is added to or removed from the active view,
	// a change value is sent on this channel.
	//
	// The active peer set will block on writes to this channel,
	// so it is recommended that the channel is buffered
	// and that a dedicated goroutine is reading from it.
	//
	// In tests, it may suffice to use a large buffered channel,
	// to avoid setting up a separate reader goroutine.
	ConnectionChanges chan<- dconn.Change
}

func NewActiveView(ctx context.Context, log *slog.Logger, cfg ActiveViewConfig) *ActiveView {
	if cfg.ConnectionChanges == nil {
		panic(errors.New("BUG: cfg.ConnectionChanges must not be nil"))
	}

	seeders := max(2, cfg.Seeders)
	workers := max(4, cfg.Workers)

	a := &ActiveView{
		log: log,

		// Not trying to pre-size these, for now at least.
		byCA:   map[dcert.CACertHandle]iPeer{},
		byLeaf: map[dcert.LeafCertHandle]iPeer{},

		dconnByLeafCert: map[dcert.LeafCertHandle]dconn.Conn{},

		processors: map[dcert.CACertHandle]*peerInboundProcessor{},

		// Unbuffered because the caller blocks on these requests anyway.
		addRequests:            make(chan addRequest),
		removeRequests:         make(chan removeRequest),
		checkConnAddrRequests:  make(chan checkConnAddrRequest),
		checkConnChainRequests: make(chan checkConnChainRequest),

		// We don't want these to block.
		// Unless otherwise noted, these are sized with arbitrary guesses.
		forwardJoinsToNetwork: make(chan forwardJoinToNetwork, 8),
		initiatedShuffles:     make(chan initiatedShuffle, 4),

		// Channels that flow back upward to the kernel.
		forwardJoinsFromNetwork: cfg.ForwardJoinsFromNetwork,
		shufflesFromPeers:       cfg.ShufflesFromPeers,
		shuffleRepliesFromPeers: cfg.ShuffleRepliesFromPeers,

		// Channels that flow out to the application.
		connectionChanges: cfg.ConnectionChanges,

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

	woCh := dfanout.WorkerOutputChannels{
		ShuffleRepliesFromPeers: cfg.ShuffleRepliesFromPeers,
	}

	for i := range workers {
		go dfanout.RunWorker(
			ctx,
			log.With("worker_idx", i),
			&a.wg,
			a.workChannels,
			woCh,
		)
	}

	return a
}

func (a *ActiveView) Wait() {
	a.processorWG.Wait()
	a.wg.Wait()
}

func (a *ActiveView) mainLoop(ctx context.Context) {
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
			for _, p := range a.byCA {
				p.Conn.CloseWithError(1, "TODO: ungraceful shutdown due to context cancellation: "+context.Cause(ctx).Error())
			}

			return

		case req := <-a.addRequests:
			a.handleAddRequest(ctx, req)

		case req := <-a.removeRequests:
			a.handleRemoveRequest(ctx, req)

		case req := <-a.checkConnAddrRequests:
			a.handleCheckConnAddrRequest(req)

		case req := <-a.checkConnChainRequests:
			a.handleCheckConnChainRequest(req)

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
func (a *ActiveView) Add(ctx context.Context, p Peer) error {
	resp := make(chan struct{})
	req := addRequest{
		IPeer: p.toInternal(),

		Resp: resp,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while making add request: %w", context.Cause(ctx),
		)

	case a.addRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while waiting for add response: %w", context.Cause(ctx),
		)

	case <-resp:
		return nil
	}
}

func (a *ActiveView) handleAddRequest(ctx context.Context, req addRequest) {
	if _, ok := a.byCA[req.IPeer.CACertHandle]; ok {
		// We might not want to panic here if and when allowing active connections
		// to "cousin" peers (who have the same CA and are highly trusted).
		panic(fmt.Errorf(
			"BUG: attempted to add peer with CA handle %q when one already existed",
			req.IPeer.CACertHandle.String(),
		))
	}

	// Channel for the peerInboundProcessor to send to the application connection.
	appStreams := make(chan *dquicwrap.Stream, 4) // TODO: what is the right size?

	a.byCA[req.IPeer.CACertHandle] = req.IPeer
	a.byLeaf[req.IPeer.LeafCertHandle] = req.IPeer

	a.processorWG.Add(1)
	a.processors[req.IPeer.CACertHandle] = newPeerInboundProcessor(
		ctx,
		a.log.With("peer_inbound_processor", req.IPeer.Conn.RemoteAddr().String()),
		pipConfig{
			Peer:       req.IPeer.ToPeer(),
			ActiveView: a,

			DynamicHandlers: 4, // TODO: needs to be configurable.

			ApplicationStreams: appStreams,
		},
	)

	// Closing the response allows the kernel to unblock.
	close(req.Resp)

	// Now we need to notify of the new connection.
	// We expect the other end of the channel to be actively reading,
	// or at least to have buffered the channel.

	// For this application-layer connection,
	// we must make sure their AcceptStream calls
	// do not interfere with our protocol layer AcceptStream;
	// hence the dquicwrap wrapper.
	newConn := dconn.Conn{
		QUIC: dquicwrap.NewConn(req.IPeer.Conn, appStreams),

		Chain: req.IPeer.Chain,
	}
	a.dconnByLeafCert[req.IPeer.LeafCertHandle] = newConn
	select {
	case <-ctx.Done():
		a.log.Warn(
			"Context canceled while sending new connection notification",
			"cause", context.Cause(ctx),
		)
		return

	case a.connectionChanges <- dconn.Change{
		Conn:   newConn,
		Adding: true,
	}:
		// Okay.
	}
}

// Remove removes the peer with the given ID from the active set.
// An error is only returned if the given context was canceled
// before the remove operation completes.
func (a *ActiveView) Remove(ctx context.Context, pid PeerCertID) error {
	resp := make(chan struct{})
	req := removeRequest{
		PCI: pid,

		Resp: resp,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while making remove request: %w", context.Cause(ctx),
		)

	case a.removeRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while waiting for remove response: %w", context.Cause(ctx),
		)

	case <-resp:
		return nil
	}
}

func (a *ActiveView) handleRemoveRequest(ctx context.Context, req removeRequest) {
	if _, ok := a.byCA[req.PCI.caHandle]; !ok {
		panic(fmt.Errorf(
			"BUG: attempted to remove peer with CA handle %q when none existed",
			req.PCI.caHandle.String(),
		))
	}

	delete(a.byCA, req.PCI.caHandle)
	delete(a.byLeaf, req.PCI.leafHandle)

	// We delete the processor from the map we manage,
	// but we still indirectly ensure the processor finishes its work
	// by waiting on a.processorWG in a.Wait.
	//
	// TODO: we may need some distinct methods beyond just Cancel.
	a.processors[req.PCI.caHandle].Cancel()
	delete(a.processors, req.PCI.caHandle)

	dc := a.dconnByLeafCert[req.PCI.leafHandle]
	delete(a.dconnByLeafCert, req.PCI.leafHandle)

	// Begin closing the connection before announcing its removal.
	// This will unblock any local outstanding reads or writes on any stream,
	// and it should force the remote to prune the connection.
	if err := dc.QUIC.CloseWithError(
		dmsg.RemovingFromActiveView,
		"removing from active view",
	); err != nil {
		a.log.Info(
			"Error closing removed connection",
			"err", err,
		)
	}

	select {
	case <-ctx.Done():
	// We are closing, so it's fine that we don't send the change.
	case a.connectionChanges <- dconn.Change{
		Conn:   dc,
		Adding: false,
	}:
		// Okay.
	}

	close(req.Resp)
}

// HasConnectionToAddress reports whether there is an existing active connection
// that reports a RemoteAddr whose String output matches
// the given netAddr parameter.
//
// This is used indirectly through [*dragon.Node.DialAndJoin]
// to avoid the work of establishing a redundant connection.
//
// There are some reasons this could report a false negative:
//   - there is a pending, incomplete connection beginning
//   - the address passed to DialAndJoin is different from
//     the reported address on the established connection
//
// In the event of a false negative, the identical CA certificate
// discovered when dialing will cause the new connection to be closed.
func (a *ActiveView) HasConnectionToAddress(
	ctx context.Context,
	netAddr string,
) (has bool, err error) {
	req := checkConnAddrRequest{
		NetAddr: netAddr,
		Resp:    make(chan bool, 1),
	}
	select {
	case <-ctx.Done():
		return false, fmt.Errorf(
			"context canceled while checking for connection to address: %w",
			context.Cause(ctx),
		)
	case a.checkConnAddrRequests <- req:
		// Okay, wait for response.
	}

	select {
	case <-ctx.Done():
		return false, fmt.Errorf(
			"context canceled while waiting for check connection to address response: %w",
			context.Cause(ctx),
		)
	case has = <-req.Resp:
		return has, nil
	}
}

func (a *ActiveView) handleCheckConnAddrRequest(
	req checkConnAddrRequest,
) {
	for _, c := range a.dconnByLeafCert {
		if c.QUIC.RemoteAddr().String() == req.NetAddr {
			req.Resp <- true
			return
		}

	}

	req.Resp <- false
}

// HasConnectionToChain reports whether there is an existing active connection
// matching the given chain.
//
// This is used indirectly through [*dragon.Node.DialAndJoin]
// to drop a new connection that would duplicate an existing one.
func (a *ActiveView) HasConnectionToChain(
	ctx context.Context,
	chain dcert.Chain,
) (has bool, err error) {
	req := checkConnChainRequest{
		Chain: chain,
		Resp:  make(chan bool, 1),
	}
	select {
	case <-ctx.Done():
		return false, fmt.Errorf(
			"context canceled while checking for connection to chain: %w",
			context.Cause(ctx),
		)
	case a.checkConnChainRequests <- req:
		// Okay, wait for response.
	}

	select {
	case <-ctx.Done():
		return false, fmt.Errorf(
			"context canceled while waiting for check connection to chain response: %w",
			context.Cause(ctx),
		)
	case has = <-req.Resp:
		return has, nil
	}
}

func (a *ActiveView) handleCheckConnChainRequest(
	req checkConnChainRequest,
) {
	_, ok := a.dconnByLeafCert[req.Chain.LeafHandle]
	req.Resp <- ok
}

func (a *ActiveView) ForwardJoinToNetwork(
	ctx context.Context,
	m dprotoi.ForwardJoinMessage,
	excludeByCA map[dcert.CACertHandle]struct{},
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

func (a *ActiveView) handleForwardJoinToNetwork(ctx context.Context, fj forwardJoinToNetwork) {
	streams := make([]dquic.Stream, 0, len(a.byCA))
	for certHandle, p := range a.byCA {
		if _, ok := fj.Exclude[certHandle]; ok {
			// Don't send it to a peer matching the CA exclude list.
			// We use CAs here, not the leaf certificate,
			// because we aren't going to
			continue
		}
		if p.Chain.LeafHandle == fj.Msg.Chain.LeafHandle {
			// Also don't send it to the node who originated it.
			// Note that we are matching the leaf, not the root, for this.
			// This way, it is possible for two peers from the same CA
			// to get a forward join from each other
			// (where the forward join is for a peer from a different CA).
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
// to the destination peer indicated by its Chain.
func (a *ActiveView) InitiateShuffle(
	ctx context.Context,
	dstChain dcert.Chain,
	entries []dprotoi.ShuffleEntry,
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
		DstCACertHandle: dstChain.RootHandle,

		Entries: entries,
	}:
		// Okay.
		return nil
	}
}

func (a *ActiveView) handleInitiatedShuffle(ctx context.Context, is initiatedShuffle) {
	p, ok := a.byCA[is.DstCACertHandle]
	if !ok {
		a.log.Warn(
			"No peer found for shuffle destination",
		)
		return
	}

	os := dfanout.WorkOutboundShuffle{
		Chain: p.Chain,
		Msg: dprotoi.ShuffleMessage{
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

func (a *ActiveView) SendShuffleReply(
	ctx context.Context,
	s dquic.Stream,
	entries []dprotoi.ShuffleEntry,
) {
	reply := dfanout.WorkOutboundShuffleReply{
		Msg: dprotoi.ShuffleReplyMessage{
			Entries: entries,
		},
		Stream: s,
	}

	select {
	case <-ctx.Done():
		a.log.Info(
			"Context canceled while attempting to send shuffle reply work item",
			"cause", context.Cause(ctx),
		)
	case a.workChannels.OutboundShuffleReplies <- reply:
		// Okay.
	}
}
