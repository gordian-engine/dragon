package bci

import (
	"context"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dbitset"
	otrace "go.opentelemetry.io/otel/trace"
)

// bsdState is the initial bitset delta state
// required for [receiveBitsetDeltas].
type bsdState struct {
	Stream dquic.ReceiveStream
	Dec    *dbitset.AdaptiveDecoder
}

// receiveBitsetDeltas repeatedly reads bitset values
// from the stream received through sCh,
// forwarding those bitsets over the deltaUpdates channel.
//
// receiveBitsetDeltas is a shared function for both
// [RunOrigination] and [RunOutgoingRelay],
// as both of them require this behavior.
func receiveBitsetDeltas(
	ctx context.Context,
	tracer otrace.Tracer,
	wg *sync.WaitGroup,

	// Need to know the size of the bitset up front,
	// to allocate a new instance correctly.
	bsSize uint,

	// Fail if we don't receive a bitset within this timeout.
	receiveTimeout time.Duration,

	// Callback for failure cases.
	onError func(string, error),

	// Work blocks on a receive from this channel.
	sCh <-chan bsdState,

	// Outgoing channel for bitset deltas we read from the stream.
	deltaUpdates chan<- *bitset.BitSet,

	// When this channel is closed,
	// there is no more read timeout applied.
	clearTimeoutCh <-chan struct{},
) {
	defer wg.Done()

	ctx, span := tracer.Start(ctx, "receive bitset deltas")
	defer span.End()

	// Block until the stream is ready.
	var s dquic.ReceiveStream
	var dec *dbitset.AdaptiveDecoder
	select {
	case <-ctx.Done():
		return
	case x, ok := <-sCh:
		if !ok {
			// Channel was closed, so just quit.
			return
		}
		s = x.Stream
		dec = x.Dec
	}

	span.AddEvent("Ready to receive initial bitset")

	// Now the peer is going to send deltas intermittently.
	// First allocation a destination bitset.
	// We are going to separately track
	// the writing-to and reading-from bitsets.
	wbs := bitset.MustNew(bsSize)

	// The first receive is special in that it seeds the write bitset.
	if err := dec.ReceiveBitset(
		s,
		receiveTimeout,
		wbs,
	); err != nil {
		// TODO: check if timeout error,
		// then check if clearTimeout channel closed.
		onError("Failed to receive first bitset update", err)
		return
	}

	span.AddEvent("Received initial bitset")

	// Now the readable bitset is just a clone of the first update.
	// Hand it off to the other goroutine.
	// The channel is unbuffered so we know the other goroutine
	// has ownership once the send completes.
	// The other goroutine always owns the read bitset,
	// and we always own the write bitset.
	rbs := wbs.Clone()
	select {
	case <-ctx.Done():
		onError("Context canceled when sending first delta update", context.Cause(ctx))
		return
	case deltaUpdates <- rbs:
		// Okay.
	}

	span.AddEvent("Sent initial delta update to other goroutine")

	// Now that the read and write bitsets are both initialized,
	// we can handle alternating them as we receive updates.
	for {
		span.AddEvent("Awaiting next bitset")
		if err := dec.ReceiveBitset(
			s,
			receiveTimeout,
			wbs,
		); err != nil {
			// TODO: check if timeout error,
			// then check if clearTimeout channel closed.
			// Also this will fail if we get a partial read at the time of the deadline,
			// so that needs to be handled somehow.
			// A separate goroutine just for managing read deadlines
			// is a bit heavy-handed but a simple solution.
			onError("Failed to receive bitset update", err)
			return
		}

		span.AddEvent("Awaiting next bitset")
		wbs, rbs = rbs, wbs
		select {
		case <-ctx.Done():
			return
		case deltaUpdates <- rbs:
			// Okay.

		case <-clearTimeoutCh:
			receiveTimeout = -1
			clearTimeoutCh = nil
			select {
			case <-ctx.Done():
				return
			case deltaUpdates <- rbs:
				// Okay.
			}
		}
	}
}
