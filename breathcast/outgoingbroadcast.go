package breathcast

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/breathcast/internal/bci"
	"github.com/quic-go/quic-go"
)

// After sending all the datagrams of chunks,
// this byte is sent over the reliable channel
// to notify the receiver that they must
// send another update of what chunks they have.
const originationCompletion byte = 0xff

// outgoingBroadcast manages a broadcast to a peer,
// where we have the full data and the peer doesn't.
type outgoingBroadcast struct {
	log *slog.Logger

	op *BroadcastOperation
}

// RunBackground starts background goroutines
// to handle the outgoing datagrams and synchronous data,
// and also to handle the incoming bitset updates.
func (o *outgoingBroadcast) RunBackground(
	ctx context.Context, conn quic.Connection, protoHeader bci.ProtocolHeader,
) {
	o.op.wg.Add(2)

	streamReady := make(chan quic.ReceiveStream)
	bitsetUpdates := make(chan *bitset.BitSet)

	go o.writeUpdates(ctx, conn, protoHeader, streamReady, bitsetUpdates)
	go o.receiveBitsetUpdates(ctx, streamReady, bitsetUpdates)
}

// writeUpdates opens a new stream on the given connection
// in order to broadcast data to the peer.
// After the initial handshake for the stream,
// it sends unreliable datagrams for everything the peer is missing.
// Then it falls back to synchronous updates
// for any remaining missing data.
//
// writeUpdates runs in its own goroutine
// created from [*outgoingBroadcast.RunBackground].
func (o *outgoingBroadcast) writeUpdates(
	ctx context.Context,
	conn quic.Connection,
	protoHeader bci.ProtocolHeader,
	streamReady chan<- quic.ReceiveStream,
	bitsetUpdates <-chan *bitset.BitSet,
) {
	defer o.op.wg.Done()

	s, err := bci.OpenStream(ctx, conn, bci.OpenStreamConfig{
		// TODO: make these configurable.
		OpenStreamTimeout: 20 * time.Millisecond,
		SendHeaderTimeout: 20 * time.Millisecond,

		ProtocolHeader: protoHeader,
		AppHeader:      o.op.appHeader,
	})
	if err != nil {
		o.log.Info(
			"Failed to open outgoing stream",
			"err", err,
		)
		o.handleError(err)
		return
	}

	// We could let the receiving goroutine accept the first bit set,
	// but this goroutine is blocked on that work anyway,
	// so just receive it here.
	peerHas := bitset.MustNew(uint(len(o.op.datagrams)))

	if err := bci.ReceiveBitset(
		s,
		10*time.Millisecond,
		len(o.op.datagrams),
		peerHas,
	); err != nil {
		o.log.Info(
			"Failed to receive initial bitset acknowledgement to origination stream",
			"err", err,
		)
		o.handleError(err)
		return
	}

	// Now we can unblock the other goroutine.
	select {
	case <-ctx.Done():
		return
	case streamReady <- s:
		// Okay.
	}

	// We have the initial bitset from the peer,
	// so now we can start sending datagrams.
	if err := o.sendUnreliableDatagrams(s.Context(), conn, peerHas, bitsetUpdates); err != nil {
		o.log.Info(
			"Failed to send datagrams",
			"err", err,
		)
		o.handleError(err)
		return
	}

	// Note that datagrams have been sent.
	const sendCompletionTimeout = 20 * time.Millisecond // TODO: make configurable.
	if err := s.SetWriteDeadline(time.Now().Add(sendCompletionTimeout)); err != nil {
		o.log.Info(
			"Failed to set write deadline for completion",
			"err", err,
		)
		o.handleError(err)
		return
	}

	if _, err := s.Write([]byte{originationCompletion}); err != nil {
		o.log.Info(
			"Failed to write completion indicator",
			"err", err,
		)
		o.handleError(err)
		return
	}

	// Now that we've informed the peer we are done with datagrams,
	// we expect one more update before we fall back to a synchronous update.
	// It is possible that the update we read was sent before
	// the peer received our origination terminator byte, but that's fine;
	// syncSendDatagrams respects further live updates.
	select {
	case <-ctx.Done():
		return
	case upd := <-bitsetUpdates:
		peerHas.InPlaceUnion(upd)
	}

	// Send the remaining datagrams synchronously.
	if err := o.syncSendDatagrams(s, peerHas, bitsetUpdates); err != nil {
		o.log.Info("Failed to send missing chunks over synchronous channel", "err", err)
		o.handleError(err)
		return
	}
}

// receiveBitsetUpdates reads bitsets sent by the peer,
// and sends those updates over the bitsetUpdates channel
// to be consumed by the [*outgoingBroadcast.writeUpdates] goroutine.
//
// receiveBitsetUpdates runs in its own goroutine
// created from [*outgoingBroadcast.RunBackground].
func (o *outgoingBroadcast) receiveBitsetUpdates(
	ctx context.Context,
	streamReady <-chan quic.ReceiveStream,
	bitsetUpdates chan<- *bitset.BitSet,
) {
	defer o.op.wg.Done()

	// Block until the stream is ready.
	var s quic.ReceiveStream
	select {
	case <-ctx.Done():
		return
	case s = <-streamReady:
		// Okay.
	}

	// Now, the peer is going to send bitset updates intermittently.
	// First allocate a destination bitset.
	// This is the bitset that we are writing to.
	wbs := bitset.MustNew(uint(len(o.op.datagrams)))

	if err := bci.ReceiveBitset(
		s,
		10*time.Millisecond,
		len(o.op.datagrams),
		wbs,
	); err != nil {
		o.log.Info(
			"Failed to receive first bitset update",
			"err", err,
		)
		o.handleError(err)
		return
	}

	// Now the readable bitset is just a clone of the first update.
	// Hand it off to the other goroutine.
	// The channel is unbuffered so we know the other goroutine
	// has ownership once the send completes.
	rbs := wbs.Clone()
	select {
	case <-ctx.Done():
		return
	case bitsetUpdates <- rbs:
		// Okay.
	}

	// Now that the read and write bitsets are both initialized,
	// we can handle alternating them as we receive updates.
	for {
		if err := bci.ReceiveBitset(
			s,
			10*time.Millisecond,
			len(o.op.datagrams),
			wbs,
		); err != nil {
			o.log.Info(
				"Failed to receive bitset update",
				"err", err,
			)
			o.handleError(err)
			return
		}

		wbs, rbs = rbs, wbs
		select {
		case <-ctx.Done():
			return
		case bitsetUpdates <- rbs:
			// Okay.
		}
	}
}

func (o *outgoingBroadcast) handleError(e error) {
	// TODO: do something with the error here.
}

// sendUnreliableDatagrams sends the missing datagrams to the peer,
// using unreliable QUIC datagrams.
func (o *outgoingBroadcast) sendUnreliableDatagrams(
	streamCtx context.Context, conn quic.Connection,
	peerHas *bitset.BitSet,
	updates <-chan *bitset.BitSet,
) error {
	// TODO: we should be able to accept a strategy for how datagrams are sent.
	// We should expect different throttling needs, for instance.
	// There could also be other QoS concerns about datagram order.
	//
	// Until we support a strategy for this, we'll just send the chunks in order.
	// Although, a shuffled order would probably be better for network distribution.

	// How many chunks we have sent so far.
	// Counter for injecting short sleeps every so often.
	var n uint

	for i, dg := range o.op.datagrams {
		if peerHas.Test(uint(i)) {
			continue
		}

		if (n & 7) == 7 {
			// Short sleep for a chance outgoing network buffer to catch up.
			// Not totally sure if this is necessary at this point,
			// but it seems reasonable that we would not want to completely flood
			// the outgoing datagram buffer, whatever it looks like.
			sleepCh := time.After(time.Microsecond)
		CATCHUP:
			for {
				select {
				case <-streamCtx.Done():
					return fmt.Errorf(
						"stream context canceled while sending datagrams: %w",
						context.Cause(streamCtx),
					)
				case upd := <-updates:
					// Consume as many updates as we can during this sleep.
					peerHas.InPlaceUnion(upd)
				case <-sleepCh:
					break CATCHUP
				}
			}
		}

		if err := conn.SendDatagram(dg); err != nil {
			return fmt.Errorf("failed to send datagram: %w", err)
		}

		n++
	}

	return nil
}

func (o *outgoingBroadcast) syncSendDatagrams(
	s quic.SendStream,
	peerHas *bitset.BitSet,
	updates <-chan *bitset.BitSet,
) error {
	// For now we are just iterating the cleared bits in order,
	// but this would be very wasteful if multiple broadcasters were doing this.
	// It might be best if the remote could tell us something like,
	// "divide the datagrams into 16 'segments' and send me what is missing from segment 3".
	//
	// Failing that, we could at least just shuffle the iteration order.
	have := peerHas.Count()
	if have >= uint(o.op.nData) {
		// We shouldn't have reached this function, probably.
		return nil
	}
	var meta [4]byte
	for u, ok := peerHas.NextClear(0); ok; u, ok = peerHas.NextClear(u + 1) {
		// There are two pieces of metadata to send before the actual datagram.
		// The chunk index and the size of the datagram.
		binary.BigEndian.PutUint16(meta[:2], uint16(u))
		binary.BigEndian.PutUint16(meta[2:], uint16(len(o.op.datagrams[u])))

		const syncDatagramTimeout = 2 * time.Millisecond // TODO: make configurable.
		if err := s.SetWriteDeadline(time.Now().Add(syncDatagramTimeout)); err != nil {
			return fmt.Errorf(
				"failed to set write deadline when sending synchronous datagram: %w",
				err,
			)
		}

		if _, err := s.Write(meta[:]); err != nil {
			return fmt.Errorf(
				"failed to write synchronous metadata: %w", err,
			)
		}

		// Keep the same deadline for sending the actual datagram content.
		if _, err := s.Write(o.op.datagrams[u]); err != nil {
			return fmt.Errorf(
				"failed to write synchronous data: %w", err,
			)
		}

		have++
		if have >= uint(o.op.nData) {
			return nil
		}

		// Didn't have enough to quit, so mark the chunk as sent.
		peerHas.Set(u)

		// Non-blocking check for remote bitset updates.
		select {
		case upd := <-updates:
			if upd.Any() {
				// Only union and re-set the have count if any bit is set.
				peerHas.InPlaceUnion(upd)
				have = peerHas.Count()
				if have >= uint(o.op.nData) {
					return nil
				}
			}
		default:
			// Nothing.
		}
	}

	return nil
}
