package bci

import (
	"context"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/quic-go/quic-go"
)

// bsdState is the initial bitset delta state
// required for [receiveBitsetDeltas].
type bsdState struct {
	Stream quic.ReceiveStream
	Dec    *CombinationDecoder
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
	wg *sync.WaitGroup,
	bsSize uint,
	receiveTimeout time.Duration,
	onError func(string, error),
	sCh <-chan bsdState,
	deltaUpdates chan<- *bitset.BitSet,
	clearTimeout <-chan struct{},
) {
	defer wg.Done()

	// Block until the stream is ready.
	var s quic.ReceiveStream
	var dec *CombinationDecoder
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

	// Now that the read and write bitsets are both initialized,
	// we can handle alternating them as we receive updates.
	for {
		if err := dec.ReceiveBitset(
			s,
			receiveTimeout,
			wbs,
		); err != nil {
			// TODO: check if timeout error,
			// then check if clearTimeout channel closed.
			onError("Failed to receive bitset update", err)
			return
		}

		wbs, rbs = rbs, wbs
		select {
		case <-ctx.Done():
			return
		case deltaUpdates <- rbs:
			// Okay.

		case <-clearTimeout:
			receiveTimeout = -1
			clearTimeout = nil
			select {
			case <-ctx.Done():
				return
			case deltaUpdates <- rbs:
				// Okay.
			}
		}
	}
}
