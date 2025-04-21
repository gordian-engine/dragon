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
	"github.com/gordian-engine/dragon/internal/dchan"
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

// RunBackground starts background goroutines
// to handle the outgoing bitset updates and the incoming synchronous data.
func (i *incomingBroadcast) RunBackground(ctx context.Context, s quic.Stream) {
	i.op.wg.Add(2)

	haveLeaves := i.state.pt.HaveLeaves()
	addedLeaves := i.state.addedLeafIndices

	go i.runBitsetUpdates(ctx, s, haveLeaves.Clone(), addedLeaves)
	go i.acceptSyncUpdates(ctx, s, haveLeaves.Clone(), addedLeaves)

	// TODO: refactor this into a proper method.
	// Canceling the stream read here will immediately unblock
	// the acceptSyncUpdates goroutine,
	// if it is in the middle of a blocking read.
	// The runBitsetUpdates just writes and should end itself properly.
	i.op.wg.Add(1)
	go func() {
		defer i.op.wg.Done()

		select {
		case <-ctx.Done():
			return
		case <-s.Context().Done():
			return
		case <-i.op.dataReady:
			// TODO: use a proper constant for this code.
			s.CancelRead(0x123456)
		}
	}()
}

func (i *incomingBroadcast) runBitsetUpdates(
	ctx context.Context, s quic.SendStream,
	haveLeaves *bitset.BitSet, addedLeaves *dchan.Multicast[uint],
) {
	defer i.op.wg.Done()

	// We need to send the first update immediately.
	// This is the only time we send the entire bitset.
	// Subsequent updates are just a delta from the last update.
	// Most updates should be small,
	// which means they can be encoded in fewer bytes across the wire.

	var combIdx big.Int
	bsBuf, err := i.sendBitset(s, haveLeaves, &combIdx, nil)
	if err != nil {
		i.log.Info(
			"Failed to send bitset",
			"err", err,
		)
		i.handleError(err)
		return
	}

	// We own the haveLeaves bitset already.
	// Since we've sent the initial set,
	// we can now clear it out and rename it as delta.
	delta := haveLeaves
	delta.ClearAll()

	const updateDur = 2 * time.Millisecond // TODO: make configurable.
	due := time.NewTimer(updateDur)
	defer due.Stop()
	for {
		select {
		case <-ctx.Done():
			cause := context.Cause(ctx)
			i.log.Info(
				"Context canceled while sending bitset updates",
				"cause", cause,
			)
			i.handleError(cause)
			return
		case <-i.op.dataReady:
			// We have the data now.
			// TODO: do we need to close the stream somehow,
			// or does that happen somewhere else?
			return
		case <-addedLeaves.Ready:
			delta.Set(addedLeaves.Val)
			addedLeaves = addedLeaves.Next
		case _ = <-due.C:
			bsBuf, err = i.sendBitset(s, delta, &combIdx, bsBuf)
			if err != nil {
				i.log.Info(
					"Failed to send bitset in update loop",
					"err", err,
				)
				i.handleError(err)
				return
			}

			delta.ClearAll()

			due.Reset(updateDur)
		}
	}
}

// sendBitset writes the compressed version of bs to the stream.
func (i *incomingBroadcast) sendBitset(
	s quic.SendStream, bs *bitset.BitSet, combIdx *big.Int, buf []byte,
) ([]byte, error) {
	k := uint16(bs.Count())
	calculateCombinationIndex(int(i.op.nChunks), bs, combIdx)

	// We need buf to accommodate 4 bytes of metadata
	// plus the size of the combination index.
	ciByteCount := (combIdx.BitLen() + 7) / 8
	sz := 4 + ciByteCount
	if cap(buf) < sz {
		buf = make([]byte, sz)
	} else {
		buf = buf[:sz]
	}

	// Now write the metadata.
	binary.BigEndian.PutUint16(buf[:2], k)
	binary.BigEndian.PutUint16(buf[2:4], uint16(ciByteCount))

	// The actual combination index.
	_ = combIdx.FillBytes(buf[4:])

	const sendBitsetTimeout = 5 * time.Millisecond // TODO: make configurable.
	if err := s.SetWriteDeadline(time.Now().Add(sendBitsetTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set write deadline: %w", err)
	}

	if _, err := s.Write(buf); err != nil {
		return nil, fmt.Errorf("failed to write bitset: %w", err)
	}

	return buf, nil
}

func (i *incomingBroadcast) acceptSyncUpdates(
	ctx context.Context, s quic.ReceiveStream,
	haveLeaves *bitset.BitSet, addedLeaves *dchan.Multicast[uint],
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

	// Now we read as many synchronous datagram messages as we need.
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
		case <-addedLeaves.Ready:
			haveLeaves.Set(addedLeaves.Val)
			addedLeaves = addedLeaves.Next

			if haveLeaves.Count() >= uint(i.op.nData) {
				// We've have everything.
				// TODO: do we need a way to close the stream here?
				return
			}

			// Restart loop in case there are more leaves to account for.
			continue
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
				"Failed to read synchronous metadata",
				"err", err,
			)
			i.handleError(err)
			return
		}

		// We have the metadata, so refresh the leaves
		// before we decide whether to process or skip the data.
	REFRESH_LEAVES:
		for {
			select {
			case <-ctx.Done():
				i.log.Info(
					"Context canceled while refreshing leaves",
					"cause", context.Cause(ctx),
				)
				i.handleError(context.Cause(ctx))
				return
			case <-i.op.dataReady:
				// We have everything; nothing left to do.
				return
			case <-addedLeaves.Ready:
				haveLeaves.Set(addedLeaves.Val)
				addedLeaves = addedLeaves.Next

				if haveLeaves.Count() >= uint(i.op.nData) {
					// We've have everything.
					// TODO: do we need a way to close the stream here?
					return
				}

				// Restart loop in case there are more leaves to account for.
				continue
			default:
				break REFRESH_LEAVES
			}
		}

		// We still need more leaves.
		idx := binary.BigEndian.Uint16(meta[:2])
		sz := binary.BigEndian.Uint16(meta[2:])

		// TODO: validate that sz matches expected limits.

		if haveLeaves.Test(uint(idx)) {
			// We don't need this leaf in particular.

			// TODO: discarding data could be a signal to refresh our bitsets to peers.

			if _, err := io.CopyN(io.Discard, s, int64(sz)); err != nil {
				i.log.Info(
					"Failed to discard unneeded synchronous data",
					"err", err,
				)
				i.handleError(err)
				return
			}

			continue
		}

		buf := make([]byte, sz)

		if _, err := io.ReadFull(s, buf[:]); err != nil {
			i.log.Info(
				"Failed to read synchronous data",
				"err", err,
			)
			i.handleError(err)
			return
		}

		if err := i.op.HandleDatagram(ctx, buf); err != nil {
			i.log.Info(
				"Failed to handle synchronous data",
				"err", err,
			)
			i.handleError(err)
			return
		}
	}
}

func (i *incomingBroadcast) handleError(e error) {
	// TODO: do something with the error here.
}
