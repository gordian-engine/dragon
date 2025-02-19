package dps

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Active handles the network interactions for an active peer set.
type Active struct {
	log *slog.Logger

	// Wait group for directly owned goroutines.
	wg sync.WaitGroup

	// Wait group for workers' main loops.
	workerWG sync.WaitGroup

	// Allow looking up a peer by its CA or its own SPKI.
	// Since an iPeer only contains references,
	// we can deal with the peer by value.
	byCASPKI   map[caSPKI]iPeer
	byLeafSPKI map[leafSPKI]iPeer

	workers map[caSPKI]*peerWorker

	addRequests    chan addRequest
	removeRequests chan removeRequest
}

// Type aliases to avoid mistakenly accessing a map incorrectly.
type (
	caSPKI   string
	leafSPKI string
)

type ActiveConfig struct{}

func NewActivePeerSet(ctx context.Context, log *slog.Logger, cfg ActiveConfig) *Active {
	a := &Active{
		log: log,

		// Not trying to pre-size these, for now at least.
		byCASPKI:   map[caSPKI]iPeer{},
		byLeafSPKI: map[leafSPKI]iPeer{},
		workers:    map[caSPKI]*peerWorker{},

		// Unbuffered because the caller blocks on these requests anyway.
		addRequests:    make(chan addRequest),
		removeRequests: make(chan removeRequest),
	}

	a.wg.Add(1)
	go a.mainLoop(ctx)

	return a
}

func (a *Active) Wait() {
	a.wg.Wait()
}

func (a *Active) mainLoop(ctx context.Context) {
	defer a.wg.Done()

	for {
		select {
		case <-ctx.Done():
			a.log.Info("Main loop quitting due to context cancellation", "cause", context.Cause(ctx))
			return

		case req := <-a.addRequests:
			a.handleAddRequest(ctx, req)

		case req := <-a.removeRequests:
			a.handleRemoveRequest(req)
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

	a.workerWG.Add(1)
	a.workers[req.IPeer.CASPKI] = newPeerWorker(
		ctx,
		a.log.With("worker", req.IPeer.Conn.RemoteAddr().String()),
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

	// We delete the worker from the map we manage,
	// but we still indirectly ensure the worker finishes its work
	// by waiting on a.workerWG in a.Wait.
	//
	// TODO: we may need some distinct methods beyond just Cancel.
	a.workers[req.PCI.caSPKI].Cancel()
	delete(a.workers, req.PCI.caSPKI)

	close(req.Resp)
}
