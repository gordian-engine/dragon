package dps

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

type peerWorker struct {
	log *slog.Logger

	// Connection and streams.
	p Peer

	// Backreference to parent.
	// Once this type is more complete,
	// it will probably be better to only reference individual fields on a,
	// instead of holding a whole reference to it.
	a *Active

	// Own wait group, unrelated to Active.
	// This only tracks the separate worker goroutines,
	// not the main loop.
	wg sync.WaitGroup

	// Called from the Cancel method.
	// Needed for finer-grained control over shutdown,
	// in particular when the peer is removed from the active set.
	cancel context.CancelCauseFunc

	mainLoopDone chan struct{}
}

func newPeerWorker(
	ctx context.Context, log *slog.Logger,
	p Peer, a *Active,
) *peerWorker {
	ctx, cancel := context.WithCancelCause(ctx)

	w := &peerWorker{
		log: log,

		p: p,

		a: a,

		cancel: cancel,

		mainLoopDone: make(chan struct{}),
	}

	// The main loop is not part of the wait group.
	go w.mainLoop(ctx)

	w.wg.Add(3)
	go w.handleIncomingAdmission()
	go w.handleIncomingDisconnect()
	go w.handleIncomingShuffle()

	return w
}

func (w *peerWorker) mainLoop(ctx context.Context) {
	// Closing the parent-owned wait group
	// prevents us from needing to do any kind of messaging to the ActivePeerSet,
	// which could more easily result in a deadlock.
	defer w.a.workerWG.Done()

	for {
		select {
		case <-ctx.Done():
			w.log.Info("Main loop stopping due to context cancellation", "cause", context.Cause(ctx))

			// TODO: this should cancel reads on all the other streams,
			// so that we can be sure that Wait finishes.
			w.wg.Wait()
			return
		}
	}
}

func (w *peerWorker) Cancel() {
	// TODO: better error handling with the cancel cause func.
	w.cancel(errors.New("worker manually canceled"))
}

func (w *peerWorker) handleIncomingAdmission() {
	defer w.wg.Done()

	w.p.Admission.SetReadDeadline(time.Time{})

	// TODO: need protocol handler for this.
}

func (w *peerWorker) handleIncomingDisconnect() {
	defer w.wg.Done()

	w.p.Disconnect.SetReadDeadline(time.Time{})

	// TODO: need protocol handler for this.
}

func (w *peerWorker) handleIncomingShuffle() {
	defer w.wg.Done()

	w.p.Shuffle.SetReadDeadline(time.Time{})

	// TODO: need protocol handler for this.
}
