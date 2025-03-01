package dpeerset

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/internal/dmsg"
	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/gordian-engine/dragon/internal/dproto/dpadmission"
	"github.com/gordian-engine/dragon/internal/dproto/dpdynamic"
	"github.com/gordian-engine/dragon/internal/dqw"
	"github.com/quic-go/quic-go"
)

// peerInboundProcessor handles the work involved with accepting messages
// from a single peer.
type peerInboundProcessor struct {
	log *slog.Logger

	// The Peer holds the connection and streams
	// whose work this worker is responsible for.
	peer Peer

	// When observing a forward join,
	// feed it back towards the kernel through this channel.
	forwardJoinsFromNetwork chan<- dmsg.ForwardJoinFromNetwork
	// Same for shuffles.
	shufflesFromPeers chan<- dmsg.ShuffleFromPeer

	// Upon accepting a dynamic stream and identifying it as an application stream,
	// send it out to this channel, which the application should be consuming.
	appStreams chan<- *dqw.Stream

	// Wait group for the processor's main loop.
	// Used by the owning active peer set
	// to know when its processors have all finished.
	mainLoopWG *sync.WaitGroup

	// Own wait group, unrelated to Active.
	// This only tracks the separate worker goroutines,
	// not the main loop.
	wg sync.WaitGroup

	// Called from the Cancel method.
	// Needed for finer-grained control over shutdown,
	// in particular when the peer is removed from the active set.
	cancel context.CancelCauseFunc
}

// pipConfig is the configuration for a peerInboundProcessor.
type pipConfig struct {
	// The peer from which the processor receives and processes messages.
	Peer Peer

	// The owner of the peerInboundProcessor.
	ActiveView *ActiveView

	// How many dynamic handlers to run.
	// Dynamic handlers are goroutines that do initial handling of new QUIC streams.
	DynamicHandlers int

	// When an application stream is detected, send it on this channel.
	ApplicationStreams chan<- *dqw.Stream
}

func newPeerInboundProcessor(
	ctx context.Context, log *slog.Logger, cfg pipConfig,
) *peerInboundProcessor {
	if cfg.DynamicHandlers <= 0 {
		panic(fmt.Errorf(
			"BUG: pipConfig.DynamicHandlers must be positive (got %d)", cfg.DynamicHandlers,
		))
	}

	// We need a cancelable root context for the type,
	// because a failed message on one stream needs to
	// stop all the work for the peer.
	ctx, cancel := context.WithCancelCause(ctx)

	p := &peerInboundProcessor{
		log: log,

		peer: cfg.Peer,

		forwardJoinsFromNetwork: cfg.ActiveView.forwardJoinsFromNetwork,
		shufflesFromPeers:       cfg.ActiveView.shufflesFromPeers,

		appStreams: cfg.ApplicationStreams,

		mainLoopWG: &cfg.ActiveView.processorWG,

		cancel: cancel,
	}

	// Usually we run the main goroutine first,
	// but in this case there are some tests that race with context cancellation.
	// Ensuring the wait group is synchronously added
	// before we start the main loop,
	// avoids that data race in test.
	// That data race seems unlikely to happen in a real system
	// that starts and is expected to stay running for a long time.
	p.wg.Add(2)
	go p.acceptDynamicStreams(ctx, cfg.DynamicHandlers)
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
	p.cancel(errors.New("peer inbound processor manually canceled"))
}

// fail cancels the processor.
// This is used internally to the processor,
// so that one invalid message ends up closing the entire processor.
func (p *peerInboundProcessor) fail(e error) {
	p.cancel(e)
}

// acceptDynamicStreams accepts new streams on the peer's connection
// and then passes that stream to worker goroutines,
// either to process protocol-level messages
// or to hand the work off to the application.
//
// hLimit is the maximum number of handler goroutines to start.
//
// Only one instance of this goroutine is started, in [newPeerInboundProcessor].
func (p *peerInboundProcessor) acceptDynamicStreams(
	ctx context.Context,
	hLimit int,
) {
	defer p.wg.Done()

	// Channel that dynamic stream handlers read from.
	// It must be unbuffered so that we know the stream is being handled
	// before we accept the next stream.
	ch := make(chan quic.Stream)

	for {
		s, err := p.peer.Conn.AcceptStream(ctx)
		if err != nil {
			p.fail(fmt.Errorf("failed to accept stream: %w", err))
			return
		}

		// We are lazily creating goroutines here,
		// only if the new stream cannot be immediately handled
		// and if we have not reached the goroutine limit.
		if hLimit > 0 {
			select {
			case ch <- s:
				// Success.
				continue
			default:
				// Start another goroutine for it.
				// We could have passed s as an initial argument to handleDynamicStreams,
				// but that complicates the loop enough that it doesn't seem
				// like a worthwhile optimization.
				p.wg.Add(1)
				go p.handleDynamicStreams(ctx, ch)
				hLimit--
			}
		}

		select {
		case <-ctx.Done():
			p.fail(fmt.Errorf(
				"context canceled while sending dynamic stream to handler: %w",
				context.Cause(ctx),
			))
			return
		case ch <- s:
			// Okay.
		}
	}
}

func (p *peerInboundProcessor) handleDynamicStreams(
	ctx context.Context,
	ch <-chan quic.Stream,
) {
	defer p.wg.Done()

	proto := dpdynamic.Protocol{
		Log: p.log.With("protocol", "dynamic"),
		Cfg: dpdynamic.Config{
			IdentifyStreamTimeout: 50 * time.Millisecond,
		},
	}

	for {
		// The goroutine is started with a valid stream,
		// so we handle work before reading from the channel.
		var s quic.Stream
		select {
		case <-ctx.Done():
			p.fail(fmt.Errorf(
				"context canceled while waiting for dynamic stream: %w",
				context.Cause(ctx),
			))
			return
		case s = <-ch:
			// Okay, do main handling.
		}

		res, err := proto.Run(ctx, s)
		if err != nil {
			p.fail(fmt.Errorf("failed to run dynamic protocol: %w", err))
			return
		}

		if res.ShuffleMessage != nil {
			p.handleShuffleFromPeer(ctx, s, *res.ShuffleMessage)
			continue
		}

		if res.ApplicationProtocolID >= 128 { // TODO: this should be a constant somewhere.
			select {
			case <-ctx.Done():
				p.fail(fmt.Errorf(
					"context canceled while sending stream to application: %w",
					context.Cause(ctx),
				))
				return
			case p.appStreams <- dqw.NewStream(s, res.ApplicationProtocolID):
				continue
			}
		}

		panic(fmt.Errorf(
			"BUG: dynamic protocol accepted but unhandled with result: %v",
			res,
		))
	}
}

func (p *peerInboundProcessor) handleShuffleFromPeer(
	ctx context.Context,
	s quic.Stream,
	sm dproto.ShuffleMessage,
) {
	// The shuffle message we've parsed needs to go back to the view manager.
	// So we send it on a channel back to the kernel first,
	// which will delegate it correctly.
	sfp := dmsg.ShuffleFromPeer{
		Src:    p.peer.Chain,
		Stream: s,
		Msg:    sm,
	}

	select {
	case <-ctx.Done():
		p.fail(fmt.Errorf(
			"context canceled while sending shuffle from peer: %w",
			context.Cause(ctx),
		))
		return
	case p.shufflesFromPeers <- sfp:
		// Done handling the inbound side of this stream.
		// The kernel owns the stream now.
	}
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

			case p.forwardJoinsFromNetwork <- dmsg.ForwardJoinFromNetwork{
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
