package breathcast

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/quic-go/quic-go"
)

// broadcastAccepter is a helper type for [RelayOperation]
// to accept an broadcast from a peer.
// It updates the RelayOperation as new information is received,
// and it informs the peer of what shards are needed.
type broadcastAccepter struct {
	log *slog.Logger

	op *RelayOperation
}

// run is the main loop for a broadcastAccepter.
// It is not intended to be called directly,
// but rather is the terminal state of other methods
// like [*broadcastAccepter.AcceptFromEmpty].
func (w *broadcastAccepter) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		}
	}
}

// AcceptFromEmpty handles a new broadcast message,
// responding that we have no shards yet.
func (w *broadcastAccepter) AcceptFromEmpty(ctx context.Context, s quic.Stream) {
	defer w.op.workerWG.Done()

	if err := s.SetWriteDeadline(time.Now().Add(w.op.ackTimeout)); err != nil {
		w.handleStreamError(fmt.Errorf("failed to set write deadline before sending ack: %w", err))
		return
	}

	// This is a fixed response in this method;
	// we have no existing chunks, so we indicate as much to the sender.
	if _, err := s.Write([]byte{0}); err != nil {
		w.handleStreamError(fmt.Errorf("failed to write have-nothing acknowledgement: %w", err))
		return
	}

	// Now we wait as long as necessary to receive the finished confirmation,
	// while the remote is sending us datagrams in the background.
	//
	// It might be better to put a reasonable timeout on this.
	//
	// And in fact this may need to move to its own goroutine,
	// so that the primary goroutine here can go into w.run
	// while we wait for the confirmation.
	if err := s.SetReadDeadline(time.Time{}); err != nil {
		w.handleStreamError(fmt.Errorf("failed to clear read deadline waiting for finish confirmation: %w", err))
		return
	}

	var buf [1]byte
	if _, err := io.ReadFull(s, buf[:]); err != nil {
		// TODO: if we got all the data,
		// the CloseStreamOnDataReady goroutine would have called s.CancelRead,
		// which would cause an error here, that we need to properly handle.
		w.handleStreamError(fmt.Errorf("failed to read finish confirmation byte: %w", err))
		return
	}

	if buf[0] != originationCompletion {
		w.handleStreamError(fmt.Errorf(
			"expected 0x%x finish confirmation byte, got 0x%x",
			originationCompletion, buf[0],
		))
		return
	}

	// Now that the sender has finished the unreliable sends,
	// we have to tell the sender what we still need.
	// To do that, we have to query the relay operation.
	totalChunks := uint(w.op.nData) + uint(w.op.nParity)
	bs := bitset.MustNew(totalChunks)
	ready := make(chan struct{})
	req := bitsetRequest{
		BS:   bs,
		Resp: ready,
	}
	select {
	case <-ctx.Done():
		// Just return without logging in this case.
		return
	case w.op.bitsetRequests <- req:
		// Okay.
	}

	// Now wait for the main loop to respond,
	select {
	case <-ctx.Done():
		// Just return without logging in this case.
		return
	case <-ready:
		// Okay.
	}

	// Our bitset is up to date.
	// Build the compressed representation.
	var combIdx big.Int
	calculateCombinationIndex(int(totalChunks), bs, &combIdx)

	// TODO: get this timeout from configuration instead.
	const bitsetTimeout = 50 * time.Millisecond
	if err := s.SetWriteDeadline(time.Now().Add(bitsetTimeout)); err != nil {
		w.handleStreamError(fmt.Errorf("failed to set bitset deadline: %w", err))
		return
	}

	// Writing the bitset requires two pieces of metadata.
	// The uint16 k (as in n choose k),
	// and the size of the binary representation.
	// The binary representation could be more than 255 bytes,
	// but it should never be more than 65k bytes;
	// so we represent that as a uint16 as well.
	var meta [4]byte
	binary.BigEndian.PutUint16(meta[:2], uint16(bs.Count()))
	ciByteCount := (combIdx.BitLen() + 7) / 8
	binary.BigEndian.PutUint16(meta[2:], uint16(ciByteCount))
	if _, err := s.Write(meta[:]); err != nil {
		w.handleStreamError(fmt.Errorf(
			"failed to set write bitset metadata: %w", err,
		))
		return
	}

	// For now we are going to use Bytes directly,
	// even though that allocates a new slice.
	if _, err := s.Write(combIdx.Bytes()); err != nil {
		w.handleStreamError(fmt.Errorf(
			"failed to set write bitset metadata: %w", err,
		))
		return
	}

	// TODO: now we need to begin reading back datagrams
	// sent over this reliable stream.

	// Standard processing now.
	w.run(ctx)
}

func (w *broadcastAccepter) handleStreamError(e error) {
	// TODO: this should feed back up somewhere to close the stream,
	// and possibly close the connection too.
	w.log.Warn("Error when handling stream", "err", e)
}

// CloseStreamOnDataReady observes w's RelayOperation
// to detect when the data has been ready.
// It sends a particular error code indicating a clean shutdown,
// to the remote end.
func (w *broadcastAccepter) CloseStreamOnDataReady(ctx context.Context, s quic.Stream) {
	defer w.op.workerWG.Done()

	select {
	case <-ctx.Done():
		// Quitting.
		return
	case <-s.Context().Done():
		// Stream otherwise closed somehow.
		return
	case <-w.op.dataReady:
		// We don't need the stream anymore.
		// TODO: move this constant somewhere meaningful,
		// and figure out what other codes would be relevant here.
		const broadcastReceived quic.StreamErrorCode = 0x1234_5678
		s.CancelRead(broadcastReceived)
	}
}
