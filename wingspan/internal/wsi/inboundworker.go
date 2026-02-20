package wsi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dtrace"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
)

// InboundWorker handles an inbound unidirection QUIC stream,
// consulting its [wspacket.InboundRemoteState]
// and sending inbound packets to the [wspacket.CentralState]
// belonging to the worker's owning [Session].
type InboundWorker[PktIn, DeltaIn, DeltaOut any] struct {
	log *slog.Logger

	tracer dtrace.Tracer

	// Channel owned by the session.
	// Parsed packets go to the session to fan out to [OutboundWorker] instances.
	inboundDeltaArrivals chan<- inboundDeltaArrival[DeltaIn]

	// Set in the Run method.
	// Simpler as a field than passing around unexported methods here.
	deltas *dpubsub.Stream[DeltaOut]
}

// NewInboundWorker returns a new InboundWorker.
func NewInboundWorker[PktIn, DeltaIn, DeltaOut any](
	log *slog.Logger,
	tracer dtrace.Tracer,
	inboundDeltaArrivals chan<- inboundDeltaArrival[DeltaIn],
) *InboundWorker[PktIn, DeltaIn, DeltaOut] {
	return &InboundWorker[PktIn, DeltaIn, DeltaOut]{
		log: log,

		tracer: tracer,

		inboundDeltaArrivals: inboundDeltaArrivals,
	}
}

// InboundStream is the set of values necessary
// to unblock [*InboundWorker.Run].
type InboundStream[PktIn, DeltaIn, DeltaOut any] struct {
	Stream dquic.ReceiveStream
	State  wspacket.InboundRemoteState[PktIn, DeltaIn, DeltaOut]
	Deltas *dpubsub.Stream[DeltaOut]
}

// Run runs the main loop of the InboundWorker.
// Run is intended to be run in its own goroutine.
func (w *InboundWorker[PktIn, DeltaIn, DeltaOut]) Run(
	ctx context.Context,
	parentWG *sync.WaitGroup,
	inboundStreamCh <-chan InboundStream[PktIn, DeltaIn, DeltaOut],
	peerReceivedCh chan<- DeltaIn,
) {
	defer parentWG.Done()

	ctx, span := w.tracer.Start(ctx, "inbound worker main loop")
	defer span.End()

	// Wait for the stream and initial state.
	var s dquic.ReceiveStream
	var state wspacket.InboundRemoteState[PktIn, DeltaIn, DeltaOut]
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
	incomingPackets := make(chan PktIn, 4) // Arbitrary size guess.
	readerDone := make(chan struct{})
	readerCtx, cancel := context.WithCancel(ctx) // Unblock send if current goroutine stops.
	go w.readStream(readerCtx, s, state, incomingPackets, readerDone)
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
		case p := <-incomingPackets:
			if err := w.convertIncomingPacketToDelta(ctx, p, state, peerReceivedCh); err != nil {
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
// and then sends the parsed packet value on the incomingPackets channel
// (which is read in the main loop of InboundWorker).
func (w *InboundWorker[PktIn, DeltaIn, DeltaOut]) readStream(
	ctx context.Context,
	rs dquic.ReceiveStream,
	state wspacket.InboundRemoteState[PktIn, DeltaIn, DeltaOut],
	incomingPackets chan<- PktIn,
	done chan<- struct{},
) {
	defer close(done)

	ctx, span := w.tracer.Start(ctx, "read inbound stream")
	defer span.End()

	for {
		if err := rs.SetReadDeadline(time.Time{}); err != nil {
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

		p, err := state.ParsePacket(rs)
		if err != nil {
			w.log.Info(
				"Failed to parse packet",
				"err", err,
			)
			dtrace.SpanError(span, err)
			return
		}

		span.AddEvent("parsed inbound packet")

		select {
		case <-ctx.Done():
			return
		case incomingPackets <- p:
			// Okay.
		}
	}
}

// convertIncomingPacketToDelta processes a packet that was already parsed
// from the inbound stream associated with w.
func (w *InboundWorker[PktIn, DeltaIn, DeltaOut]) convertIncomingPacketToDelta(
	ctx context.Context,
	p PktIn,
	state wspacket.InboundRemoteState[PktIn, DeltaIn, DeltaOut],
	peerReceivedCh chan<- DeltaIn,
) error {
	// Consult local state first.
	err := state.CheckIncoming(p)
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

	// Now that we've done the lightweight check on the packet,
	// the state value can do any other heavy lifting required
	// for the central state to fan this value out.
	d, err := state.PacketToDelta(p)
	if err != nil {
		return fmt.Errorf("failed to convert packet to delta: %w", err)
	}

	// Before sending the delta to the central state,
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
	req := inboundDeltaArrival[DeltaIn]{
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
