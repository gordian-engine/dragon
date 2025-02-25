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

// peerInboundProcessor handles the work involved with accepting messages
// from a single peer.
type peerInboundProcessor struct {
	log *slog.Logger

	// The Peer holds the connection and streams
	// whose work this worker is responsible for.
	peer Peer

	// Backreference to parent.
	// Once this type is more complete,
	// it will probably be better to only reference individual fields on a,
	// instead of holding a whole reference to it.
	a *Active

	mainLoopWG *sync.WaitGroup

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

func newPeerInboundProcessor(
	ctx context.Context, log *slog.Logger,
	peer Peer, a *Active,
) *peerInboundProcessor {
	// We need a cancelable root context for the type,
	// because a failed message on one stream needs to
	// stop all the work for the peer.
	ctx, cancel := context.WithCancelCause(ctx)

	p := &peerInboundProcessor{
		log: log,

		peer: peer,

		a: a,

		mainLoopWG: &a.processorWG,

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
	p.wg.Add(1)
	go p.handleIncomingAdmission(ctx)

	// The main loop is not part of the wait group.
	go p.mainLoop(ctx)

	return p
}

func (p *peerInboundProcessor) mainLoop(ctx context.Context) {
	// Closing the parent-owned wait group
	// prevents us from needing to do any kind of messaging to the ActivePeerSet,
	// which could more easily result in a deadlock.
	defer p.mainLoopWG.Done()

	for {
		select {
		case <-ctx.Done():
			p.log.Info("Main loop stopping due to context cancellation", "cause", context.Cause(ctx))

			// TODO: this should cancel reads on all the other streams,
			// so that we can be sure that Wait finishes.
			p.wg.Wait()
			return
		}
	}
}

func (p *peerInboundProcessor) Cancel() {
	// TODO: better error handling with the cancel cause func.
	p.cancel(errors.New("worker manually canceled"))
}

// fail cancels the worker.
// This is used internally to the worker,
// so that one invalid message ends up closing the entire worker.
func (p *peerInboundProcessor) fail(e error) {
	p.cancel(e)
}

func (p *peerInboundProcessor) handleIncomingAdmission(ctx context.Context) {
	defer p.wg.Done()

	proto := dpadmission.Protocol{
		Log:    p.log.With("protocol", "admission"),
		Stream: p.peer.Admission,
		Cfg: dpadmission.Config{
			AcceptForwardJoinTimeout: 50 * time.Millisecond,
		},
	}

	for {
		// We can wait for as long as necessary.
		if err := p.peer.Admission.SetReadDeadline(time.Time{}); err != nil {
			p.fail(fmt.Errorf("failed to set read deadline on admission stream: %w", err))
			return
		}

		res, err := proto.Run(ctx)
		if err != nil {
			p.fail(fmt.Errorf("failed to run admission protocol: %w", err))
			return
		}

		// Only possible outcome from the protocol, currently.
		if res.ForwardJoinMessage != nil {
			// The protocol handler gets the raw bytes from the network
			// but doesn't validate it.
			fjm := *res.ForwardJoinMessage
			if err := fjm.AA.VerifySignature(fjm.Chain.Leaf); err != nil {
				p.fail(fmt.Errorf(
					"received forward join message with invalid signature: %w", err,
				))
			}

			forwarderCert := p.peer.Conn.ConnectionState().TLS.PeerCertificates[0]
			select {
			case <-ctx.Done():
				p.fail(fmt.Errorf(
					"context canceled while sending forward join from network: %w",
					context.Cause(ctx),
				))
				return

			case p.a.forwardJoinsFromNetwork <- ForwardJoinFromNetwork{
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
