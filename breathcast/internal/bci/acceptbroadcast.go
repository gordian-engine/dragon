package bci

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/quic-go/quic-go"
)

// AcceptBroadcastConfig is the configuration for [RunAcceptBroadcast].
type AcceptBroadcastConfig struct {
	WG *sync.WaitGroup

	Stream          quic.Stream
	DatagramHandler DatagramHandler

	InitialHaveLeaves *bitset.BitSet
	AddedLeaves       *dchan.Multicast[uint]

	BitsetSendPeriod time.Duration

	DataReady <-chan struct{}
}

// DatagramHandler handles new datagrams.
// In production code this will be an instance of [*breathcast.BroadcastOperation].
type DatagramHandler interface {
	HandleDatagram(context.Context, []byte) error
}

// RunAcceptBroadcast runs background goroutines to handle the receive side
// of an incoming broadcast.
// The remote may be sending a full broadcast,
// or they may be relaying incoming data that they are receiving.
func RunAcceptBroadcast(
	ctx context.Context,
	log *slog.Logger,
	cfg AcceptBroadcastConfig,
) {
	// Unbuffered because the two goroutines using this
	// need to synchronize across it.
	newHaveLeaves := make(chan *bitset.BitSet)

	cfg.WG.Add(3)
	go runPeriodicBitsetUpdates(
		ctx,
		log.With("step", "periodic_bitset_updates"),
		cfg.WG,
		cfg.Stream,
		cfg.InitialHaveLeaves.Clone(),
		cfg.AddedLeaves,
		newHaveLeaves,
		4*time.Millisecond,
		2*time.Millisecond,
		cfg.DataReady,
	)
	go acceptSyncUpdates(
		ctx,
		log.With("step", "accept_sync_updates"),
		cfg.WG,
		cfg.Stream,
		cfg.DatagramHandler,
		newHaveLeaves,
		5*time.Millisecond,
		cfg.DataReady,
	)
	go terminateStreamWhenDone(
		ctx,
		cfg.WG,
		cfg.Stream,
		cfg.DataReady,
	)
}

func runPeriodicBitsetUpdates(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	s quic.SendStream,
	haveLeaves *bitset.BitSet,
	addedLeaves *dchan.Multicast[uint],
	newHaveLeaves chan<- *bitset.BitSet,
	sendTimeout time.Duration,
	sendPeriod time.Duration,
	dataReady <-chan struct{},
) {
	defer wg.Done()

	enc := new(CombinationEncoder)

	// Send the first update immediately.
	// This is the only time we send the entire bitset.
	// Subsequent updates are just a delta from the last update.
	// Most updates should be small,
	// which means they can be encoded in fewer bytes across the wire.

	if err := enc.SendBitset(s, sendTimeout, haveLeaves); err != nil {
		log.Info("Failed to send initial bitset", "err", err)
		return
	}

	// We own the haveLeaves bitset already.
	// Since we've sent the initial set,
	// we can now clear it out and rename it as delta.
	delta := bitset.MustNew(haveLeaves.Len())
	leavesChanged := false

	// Split haveLeaves into read and write copies for simpler bookkeeping.
	haveLeavesR := haveLeaves.Clone()
	haveLeavesW := haveLeaves

	// The other goroutine is waiting on an initial copy of haveLeaves.
	select {
	case <-ctx.Done():
		log.Info(
			"Context canceled while sending initial leaves to sync update goroutine",
			"cause", context.Cause(ctx),
		)
		return
	case <-dataReady:
		// Clean shutdown.
		return
	case newHaveLeaves <- haveLeavesR:
		// Okay, keep going.
	}

	due := time.NewTimer(sendPeriod)
	defer due.Stop()
	for {
		var newHaveLeavesCh chan<- *bitset.BitSet
		if leavesChanged {
			newHaveLeavesCh = newHaveLeaves
		}
		select {
		case <-ctx.Done():
			cause := context.Cause(ctx)
			log.Info(
				"Context canceled while sending bitset updates",
				"cause", cause,
			)
			return

		case <-dataReady:
			// The terminateStreamWhenDone goroutine will clean up the stream.
			return

		case <-addedLeaves.Ready:
			bit := addedLeaves.Val
			addedLeaves = addedLeaves.Next

			delta.Set(bit)
			if !haveLeavesW.Test(bit) {
				haveLeavesW.Set(bit)
				leavesChanged = true
			}

		case newHaveLeavesCh <- haveLeavesW:
			// It's still safe to read from the write version.
			// And once we've written to that channel,
			// the remote end is no longer referencing the read version.
			haveLeavesR.InPlaceUnion(haveLeavesW)

			// Now swap the version we write.
			haveLeavesW, haveLeavesR = haveLeavesR, haveLeavesW

			// Don't try to write to the channel again until we get a new leaf.
			leavesChanged = false

		case _ = <-due.C:
			if err := enc.SendBitset(s, sendTimeout, delta); err != nil {
				log.Info(
					"Failed to send bitset in update loop",
					"err", err,
				)
				return
			}

			delta.ClearAll()

			due.Reset(sendPeriod)
		}
	}
}

// acceptSyncUpdates is a background goroutine for [RunAcceptBroadcast].
// It handle the receive-side of the stream,
// reading synchronous missed datagrams or remaining catchup as appropriate.
// The receive work is the same whether
// the remote is relaying or doing a full broadcast.
func acceptSyncUpdates(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	s quic.ReceiveStream,
	dh DatagramHandler,
	newHaveLeaves <-chan *bitset.BitSet,
	readSyncTimeout time.Duration,
	dataReady <-chan struct{},
) {
	defer wg.Done()

	// haveLeaves is an independent copy of which leaves we have.
	// The send-side of the newHaveLeaves channel gives us read-only views
	// of a bitset, and we have to copy them over our local copy.
	var haveLeaves *bitset.BitSet
	select {
	case <-ctx.Done():
		log.Info(
			"Context canceled while waiting for initial leaves",
			"cause", context.Cause(ctx),
		)
		return

	case <-dataReady:
		return

	case n := <-newHaveLeaves:
		// On the first instance, we actually create the haveLeaves instance.
		// Later receives on newHaveLeaves will copy the new value into the existing one.
		haveLeaves = n.Clone()
	}

	var oneByte [1]byte

	// This loop covers waiting for a synchronous update.
	// If the remote is a full broadcast,
	// we will only receive a "datagrams finished" indicator.
	// If the remote is relaying,
	// they will send datagrams and observe our reports of what we received,
	// and occasionally they may send a "missed datagram" indicator,
	// synchronously sending the single message to ensure we have it.
UNFINISHED:
	for {
		// We don't know when the next synchronous update will arrive,
		// so we have to clear the deadline.
		if err := s.SetReadDeadline(time.Time{}); err != nil {
			log.Info(
				"Failed to clear synchonous read deadline",
				"err", err,
			)
			return
		}

		if _, err := io.ReadFull(s, oneByte[:]); err != nil {
			log.Info(
				"Failed to read synchronous message ID byte",
				"err", err,
			)
			return
		}

		switch oneByte[0] {
		case datagramSyncMessageID:
			// Re-sync of a missed datagram.
			if err := readSingleSyncDatagram(
				ctx,
				s, dh,
				haveLeaves, newHaveLeaves,
				readSyncTimeout,
				dataReady,
			); err != nil {
				log.Info(
					"Failed to read synchronous missed datagram",
					"err", err,
				)
				return
			}
			continue UNFINISHED
		case datagramsFinishedMessageID:
			break UNFINISHED
		default:
			log.Info(
				"Received invalid message ID byte when waiting for synchronous updates",
				"byte", oneByte[0],
			)
			return
		}
	}

	// Here, we have received the datagram finished ID,
	// so we just loop until the data is ready.
	for {
		// One check before reading the next sync datagram.
		select {
		case <-ctx.Done():
			log.Info(
				"Context canceled while consuming sync datagrams",
				"cause", context.Cause(ctx),
			)
			return

		case <-dataReady:
			return

		case n := <-newHaveLeaves:
			n.CopyFull(haveLeaves)
			// Updated leaves may influence future datagrams we read.

		default:
			// Just proceed to reading the datagram.
		}

		if err := readSingleSyncDatagram(
			ctx,
			s, dh,
			haveLeaves, newHaveLeaves,
			readSyncTimeout,
			dataReady,
		); err != nil {
			log.Info(
				"Failed to read synchronous missed datagram",
				"err", err,
			)
			return
		}
	}
}

// readSingleSyncDatagram reads a full, single synchronous datagram from s.
// We expect that the datagram should be available immediately,
// due to receiving a header for a one-off sync datagram,
// or because the remote signaled that the datagrams are finished.
//
// haveLeaves and the corresponding newHaveLeaves channel give an optimistic
// view of what leaves we already have.
// If the stream contains a datagram that isn't present in the leaves we have,
// then the datagram is passed to the datagram handler.
func readSingleSyncDatagram(
	ctx context.Context,
	s quic.ReceiveStream,
	dh DatagramHandler,
	haveLeaves *bitset.BitSet,
	newHaveLeaves <-chan *bitset.BitSet,
	readSyncTimeout time.Duration,
	dataReady <-chan struct{},
) error {
	// Single read deadline for the metadata and the actual data.
	if err := s.SetReadDeadline(time.Now().Add(readSyncTimeout)); err != nil {
		return fmt.Errorf(
			"failed to set read deadline for synchronous datagram: %w", err,
		)
	}

	var meta [4]byte
	if _, err := io.ReadFull(s, meta[:]); err != nil {
		return fmt.Errorf(
			"failed to read synchronous metadata: %w", err,
		)
	}

	idx := binary.BigEndian.Uint16(meta[:2])
	sz := binary.BigEndian.Uint16(meta[2:])

	// TODO: validate that sz matches expected limits.

	// One more check to see if we need to process this datagram.
	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while receiving synchronous datagram: %w",
			context.Cause(ctx),
		)
	case <-dataReady:
		// All done.
		return nil

	case n := <-newHaveLeaves:
		// Newer than what we had before.
		n.CopyFull(haveLeaves)

	default:
		// Keep going.
	}

	if haveLeaves.Test(uint(idx)) {
		// Skip over the data.
		if _, err := io.CopyN(io.Discard, s, int64(sz)); err != nil {
			return fmt.Errorf("failed to skip redundant synchronous datagram: %w", err)
		}

		// And we've handled the datagram at this point.
		return nil
	}

	dg := make([]byte, sz)
	if _, err := io.ReadFull(s, dg); err != nil {
		return fmt.Errorf("failed to read synchronous datagram: %w", err)
	}

	// We didn't have the datagram, so try to add it.
	// This seems safe to do between parsing datagrams,
	// but we could offload it to a separate goroutine if needed.
	if err := dh.HandleDatagram(ctx, dg); err != nil {
		return fmt.Errorf("failed to handle synchronous datagram: %w", err)
	}

	return nil
}

// terminateStreamWhenDone ensures that the stream is closed
// and that currently blocked reads or writes are interrupted
// when either the outer context is canceled,
// or when the data is completed.
func terminateStreamWhenDone(
	ctx context.Context,
	wg *sync.WaitGroup,
	s quic.Stream,
	dataReady <-chan struct{},
) {
	defer wg.Done()

	select {
	case <-ctx.Done():
		// TODO: this should inspect context.Cause
		// and send an appropriate error code.
		// But for the moment we will do a simple close.
		s.CancelRead(InterruptedErrorCode)
		s.Close()
		return
	case <-dataReady:
		s.CancelRead(GotFullDataErrorCode)
		s.CancelWrite(GotFullDataErrorCode)
	}
}
