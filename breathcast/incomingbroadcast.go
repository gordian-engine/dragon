package breathcast

import (
	"context"
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

	go i.runBitsetUpdates(ctx, s)
	go i.acceptSyncUpdates(ctx, s)
}

func (i *incomingBroadcast) runBitsetUpdates(ctx context.Context, s quic.SendStream) {
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

	// TODO: loop, receiving updated bit sets and periodically sending them out.
}

func (i *incomingBroadcast) acceptSyncUpdates(ctx context.Context, s quic.ReceiveStream) {
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
