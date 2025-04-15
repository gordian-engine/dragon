package breathcast

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"
)

// incomingBroadcast manages the incoming broadcast from a peer.
// The remote may or may not have the entire data set,
// but at a minimum they have the application header.
type incomingBroadcast struct {
	log *slog.Logger

	op *BroadcastOperation

	// Store the state separately from the BroadcastOperation,
	// so that the main operation can clear its incomingState
	// when no longer needed,
	// without causing a data race on in-flight incoming broadcasts.
	state *incomingState
}

// RunBackground starts two background goroutines
// to handle the outgoing bitset updates and the incoming synchronous data.
func (i *incomingBroadcast) RunBackground(ctx context.Context, s quic.Stream) {
	i.op.wg.Add(2)

	syncUpdatesReady := make(chan struct{})

	go i.runBitsetUpdates(ctx, s, syncUpdatesReady)
	go i.acceptSyncUpdates(ctx, s, syncUpdatesReady)
}

func (i *incomingBroadcast) runBitsetUpdates(
	ctx context.Context, s quic.SendStream, syncUpdatesReady <-chan struct{},
) {
	defer i.op.wg.Done()

	// We need to send the first update immediately.
	// And first we send a single 0-byte to indicate we have nothing.
	// See (*outgoingBroadcast).receiveInitialAck for the receiving side of this stream.

	const initialAckTimeout = 20 * time.Millisecond // TODO: make configurable.
	if err := s.SetWriteDeadline(time.Now().Add(initialAckTimeout)); err != nil {
		i.log.Info(
			"Failed to set initial bitset acknowledgement deadline",
			"err", err,
		)
		i.handleError(err)
		return
	}

	initialAck := [1]byte{0}
	if _, err := s.Write(initialAck[:]); err != nil {
		i.log.Info(
			"Failed to write initial bitset acknowledgement header byte",
			"err", err,
		)
		i.handleError(err)
		return
	}

	select {
	case <-ctx.Done():
		i.log.Info(
			"Context canceled while waiting for datagram termination",
			"cause", context.Cause(ctx),
		)
		i.handleError(context.Cause(ctx))
		return
	case <-syncUpdatesReady:
		// Time to send out the updated bitset.
		// TODO: we need to actually observe the updated bitset for this.
	}

	// TODO: loop, receiving updated bit sets and periodically sending them out.
}

func (i *incomingBroadcast) acceptSyncUpdates(
	ctx context.Context, s quic.ReceiveStream, syncUpdatesReady chan<- struct{},
) {
	defer i.op.wg.Done()

	// We don't know when the first synchronous update will arrive,
	// so we have to clear the deadline.
	if err := s.SetReadDeadline(time.Time{}); err != nil {
		i.log.Info(
			"Failed to clear synchronous read deadline",
			"err", err,
		)
		i.handleError(err)
		return
	}

	var oneByte [1]byte
	if _, err := io.ReadFull(s, oneByte[:]); err != nil {
		i.log.Info(
			"Failed to read datagram termination byte",
			"err", err,
		)
		i.handleError(err)
		return
	}

	if oneByte[0] != 0xff {
		err := fmt.Errorf("expected 0xff, got 0x%x", oneByte[0])
		i.log.Info(
			"Received invalid datagram termination byte",
			"err", err,
		)
		i.handleError(err)
		return
	}

	// Now that we have received the termination byte,
	// we need to send the compressed bitset of what we have so far.
	// But we rely on the runBitsetUpdates goroutine to do that,
	// so send that signal now.
	close(syncUpdatesReady)

	// Now we read as many datagram messages as we need.
	var meta [4]byte
	for {
		// Check whether we're done.
		select {
		case <-ctx.Done():
			i.log.Info(
				"Context canceled while waiting for remaining synchronous data",
				"cause", context.Cause(ctx),
			)
			i.handleError(context.Cause(ctx))
			return
		case <-i.op.dataReady:
			// We have everything; nothing left to do.
			return
		default:
			// Keep going.
		}

		const readSyncDatagramTimeout = 5 * time.Millisecond // TODO: make configurable.
		if err := s.SetReadDeadline(time.Now().Add(readSyncDatagramTimeout)); err != nil {
			i.log.Info(
				"Failed to set read deadline for reading synchronous data",
				"err", err,
			)
			i.handleError(err)
			return
		}

		if _, err := io.ReadFull(s, meta[:]); err != nil {
			i.log.Info(
				"Failed to set read synchronous metadata",
				"err", err,
			)
			i.handleError(err)
			return
		}

		// TODO: we should actually have a read-only copy of the bit set here,
		// so that we can evaluate whether a synchronous message is new information.
		// Instead, for now, we just get the whole datagram and pass it to the operation.
		// This is inefficient but it should work for now.
		sz := binary.BigEndian.Uint16(meta[2:])
		buf := make([]byte, sz)

		if _, err := io.ReadFull(s, buf[:]); err != nil {
			i.log.Info(
				"Failed to set read synchronous data",
				"err", err,
			)
			i.handleError(err)
			return
		}

		if err := i.op.HandleDatagram(ctx, buf); err != nil {
			i.log.Info(
				"Failed to set handle synchronous data",
				"err", err,
			)
			i.handleError(err)
			return
		}
	}
}

// Run accepts incoming data on the given stream.
// The application layer must have already parsed the protocol ID,
// the broadcast ID, and the application header.
// Then the application passes the incoming broadcast
// to [*BroadcastOperation.AcceptBroadcast],
// which delegates it to this goroutine,
// if the operation still needs any data.
func (i *incomingBroadcast) Run(
	ctx context.Context,
	s quic.Stream,
) {
	// Compress the bitset before
	const writeBitsetTimeout = 20 * time.Millisecond // TODO: make configurable.
	if err := s.SetWriteDeadline(time.Now().Add(writeBitsetTimeout)); err != nil {
		i.log.Info(
			"Failed to set write deadline for outgoing bitset",
			"err", err,
		)
		i.handleError(err)
		return
	}
}

func (i *incomingBroadcast) handleError(e error) {
	// TODO: do something with the error here.
}
