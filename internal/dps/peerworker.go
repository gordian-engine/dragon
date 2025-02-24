package dps

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/internal/dproto/dpadmission"
)

// peerWorker handles the work involved with accepting messages
// from a single peer.
type peerWorker struct {
	log *slog.Logger

	// The Peer holds the connection and streams
	// whose work this worker is responsible for.
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

	// Usually we run the main goroutine first,
	// but in this case there are some tests that race with context cancellation.
	// Ensuring the wait group is synchronously added
	// before we start the main loop,
	// avoids that data race in test.
	// That data race seems unlikely to happen in a real system
	// that starts and is expected to stay running for a long time.
	w.wg.Add(3)
	go w.handleIncomingAdmission(ctx)
	go w.handleIncomingDisconnect()
	go w.handleIncomingShuffle()

	// The main loop is not part of the wait group.
	go w.mainLoop(ctx)

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

// fail cancels the worker.
func (w *peerWorker) fail(e error) {
	w.cancel(e)
}

func (w *peerWorker) handleIncomingAdmission(ctx context.Context) {
	defer w.wg.Done()

	p := dpadmission.Protocol{
		Log:    w.log.With("protocol", "admission"),
		Stream: w.p.Admission,
		Cfg: dpadmission.Config{
			AcceptForwardJoinTimeout: 50 * time.Millisecond,
		},
	}

	for {
		// We can wait for as long as necessary.
		if err := w.p.Admission.SetReadDeadline(time.Time{}); err != nil {
			w.fail(fmt.Errorf("failed to set read deadline on admission stream: %w", err))
			return
		}

		res, err := p.Run(ctx)
		if err != nil {
			w.fail(fmt.Errorf("failed to run admission protocol: %w", err))
			return
		}

		// Only possible outcome from the protocol, currently.
		if res.ForwardJoinMessage != nil {
			// The protocol handler gets the raw bytes from the network
			// but doesn't validate it.
			fjm := *res.ForwardJoinMessage
			if err := fjm.AA.VerifySignature(fjm.Chain.Leaf); err != nil {
				w.fail(fmt.Errorf(
					"received forward join message with invalid signature: %w", err,
				))
			}

			forwarderCert := w.p.Conn.ConnectionState().TLS.PeerCertificates[0]
			select {
			case <-ctx.Done():
				w.fail(fmt.Errorf(
					"context canceled while sending forward join from network: %w",
					context.Cause(ctx),
				))
				return

			case w.a.forwardJoinsFromNetwork <- ForwardJoinFromNetwork{
				Msg:           fjm,
				ForwarderCert: forwarderCert,
			}:
				// Okay.
				continue
			}
		}

		panic(errors.New(
			"IMPOSSIBLE: admission protocol returned without setting any result",
		))
	}
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
