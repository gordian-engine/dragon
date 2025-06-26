package wsi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
	"github.com/quic-go/quic-go"
)

// InboundWorker handles an inbound unidirection QUIC stream,
// consulting its [wspacket.InboundRemoteState]
// and sending inbound packets to the [wspacket.CentralState]
// belonging to the worker's owning [Session].
type InboundWorker[D any] struct {
	log *slog.Logger

	// Channel owned by the session.
	// Parsed packets go to the session to fan out to [OutboundWorker] instances.
	inboundDeltaArrivals chan<- inboundDeltaArrival[D]

	// Set in the Run method.
	// Simpler as a field than passing around unexported methods here.
	deltas *dpubsub.Stream[D]
}

// NewInboundWorker returns a new InboundWorker.
func NewInboundWorker[D any](
	log *slog.Logger,
	inboundDeltaArrivals chan<- inboundDeltaArrival[D],
) *InboundWorker[D] {
	return &InboundWorker[D]{
		log: log,

		inboundDeltaArrivals: inboundDeltaArrivals,
	}
}

// InboundStream is the set of values necessary
// to unblock [*InboundWorker.Run].
type InboundStream[D any] struct {
	Stream quic.ReceiveStream
	State  wspacket.InboundRemoteState[D]
	Deltas *dpubsub.Stream[D]
}

// Run runs the main loop of the InboundWorker.
// Run is intended to be run in its own goroutine.
func (w *InboundWorker[D]) Run(
	ctx context.Context,
	parentWG *sync.WaitGroup,
	parsePacketFn func(io.Reader) (D, error),
	inboundStreamCh <-chan InboundStream[D],
	peerReceivedCh chan<- D,
) {
	defer parentWG.Done()

	// Wait for the stream and initial state.
	var s quic.ReceiveStream
	var state wspacket.InboundRemoteState[D]
	select {
	case <-ctx.Done():
		return
	case is := <-inboundStreamCh:
		s = is.Stream
		state = is.State
		w.deltas = is.Deltas
	}

	// Now that we are set up,
	// we start a separate goroutine to handle reading from the stream.
	localReads := make(chan D, 4) // Arbitrary size guess.
	readerDone := make(chan struct{})
	readerCtx, cancel := context.WithCancel(ctx) // Unblock send if current goroutine stops.
	go w.readStream(readerCtx, s, parsePacketFn, localReads, readerDone)
	defer func() {
		<-readerDone
	}()
	defer cancel() // Must run before the blocking receive on readerDone.

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.deltas.Ready:
			val := w.deltas.Val
			w.deltas = w.deltas.Next
			if err := state.ApplyUpdateFromCentral(val); err != nil {
				w.log.Info(
					"Failed to apply local state update",
					"err", err,
				)
				return
			}
		case d := <-localReads:
			if err := w.handleLocalRead(ctx, d, state, peerReceivedCh); err != nil {
				w.log.Info(
					"Failed to handle result of local read",
					"err", err,
				)
				return
			}
		}
	}
}

// readStream parses one packet at a time from s,
// and then sends the parsed delta value on the localReads channel
// (which is part of the main loop of InboundWorker).
func (w *InboundWorker[D]) readStream(
	ctx context.Context,
	s quic.ReceiveStream,
	parsePacketFn func(io.Reader) (D, error),
	localReads chan<- D,
	done chan<- struct{},
) {
	defer close(done)

	for {
		if err := s.SetReadDeadline(time.Time{}); err != nil {
			w.log.Info(
				"Failed to set read deadline on stream",
				"err", err,
			)
			return
		}

		// TODO: this should read the first byte,
		// then set the read deadline to something reasonable
		// and pass the concatenated byte and stream
		// to the packet parsing function.
		// Otherwise the peer could send a partial packet
		// and we would be stuck here until the stream is otherwise canceled.

		delta, err := parsePacketFn(s)
		if err != nil {
			w.log.Info(
				"Failed to parse packet",
				"err", err,
			)
			return
		}

		select {
		case <-ctx.Done():
			return
		case localReads <- delta:
			// Okay.
		}
	}
}

// handleLocalRead processes a packet that was already parsed
// from the inbound stream associated with w.
func (w *InboundWorker[D]) handleLocalRead(
	ctx context.Context,
	d D,
	state wspacket.InboundRemoteState[D],
	peerReceivedCh chan<- D,
) error {
	// Consult local state first.
	err := state.CheckIncoming(d)
	if errors.Is(err, wspacket.ErrAlreadyHavePacket) {
		// We saw this data from somewhere else,
		// so nothing to do here.
		return nil
	}

	if errors.Is(err, wspacket.ErrDuplicateSentPacket) {
		return fmt.Errorf("protocol violation: %w", err)
	}

	if err != nil {
		return fmt.Errorf("failed to check incoming packet: %w", err)
	}

	// Local state was fine.
	// Before sending this to the central state,
	// attempt to inform the outbound worker of this new delta.
	select {
	case peerReceivedCh <- d:
		peerReceivedCh = nil
	default:
	}

	// Now we need to check the central state.
	// This requests blocks on the central state's main loop,
	// and this method is called from the inbound worker's main loop,
	// so we do have to process some other signals here.
	respCh := make(chan inboundDeltaResult, 1)
	req := inboundDeltaArrival[D]{
		Delta: d,

		Resp: respCh,
	}
SEND_TO_CENTRAL:
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"context canceled while sending local read to central state: %w",
				context.Cause(ctx),
			)
		case <-w.deltas.Ready:
			val := w.deltas.Val
			w.deltas = w.deltas.Next
			if err := state.ApplyUpdateFromCentral(val); err != nil {
				return fmt.Errorf(
					"failed to apply local state update while sending local read to central state: %w",
					err,
				)
			}
			continue SEND_TO_CENTRAL
		case w.inboundDeltaArrivals <- req:
			// Okay. Now need to wait for response.
			break SEND_TO_CENTRAL
		case peerReceivedCh <- d: // Channel may already have been nil.
			peerReceivedCh = nil
			continue SEND_TO_CENTRAL
		}
	}

	var res inboundDeltaResult
AWAIT_RESULT_FROM_CENTRAL:
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"context canceled while awaiting delta result from central state: %w",
				context.Cause(ctx),
			)
		case <-w.deltas.Ready:
			val := w.deltas.Val
			w.deltas = w.deltas.Next
			if err := state.ApplyUpdateFromCentral(val); err != nil {
				return fmt.Errorf(
					"failed to apply local state update awaiting delta result from central state: %w",
					err,
				)
			}
			continue AWAIT_RESULT_FROM_CENTRAL
		case res = <-respCh:
			// Process the result outside this loop.
			break AWAIT_RESULT_FROM_CENTRAL
		case peerReceivedCh <- d: // Channel may already have been nil.
			peerReceivedCh = nil
			continue AWAIT_RESULT_FROM_CENTRAL
		}
	}

	// Finally, handle the result we received from the central state.
	switch res {
	case inboundDeltaApply:
		if err := state.ApplyUpdateFromPeer(d); err != nil {
			return fmt.Errorf(
				"failed to apply update from remote: %w", err,
			)
		}

		return nil
	case inboundDeltaDrop:
		// Nothing to do.
		return nil
	case inboundDeltaReject:
		// TODO: this needs to signal a protocol violation.
		// Maybe the Session could detect this value
		// and cancel the stream at that layer.
		panic(fmt.Errorf("TODO: handle delta reject case"))
	default:
		panic(fmt.Errorf("BUG: invalid inboundDeltaResult value %d", res))
	}
}
