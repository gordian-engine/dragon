package bci

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/quic-go/quic-go"
)

// OutgoingRelayConfig is the configuration for [RunOutgoingRelay].
type OutgoingRelayConfig struct {
	// The wait group for the outgoing relay
	// lives outside the outgoing relay operation,
	// as we are typically unconcerned with a single instance.
	WG *sync.WaitGroup

	// The connection on which we will open the stream.
	Conn quic.Connection

	// The protocol header for the corresponding broadcast operation.
	ProtocolHeader ProtocolHeader

	AppHeader []byte

	// Read-only view of the datagrams that the operation has available.
	Datagrams [][]byte

	// What datagrams we are initially allowed to read.
	// The RunOutgoingRelay function takes ownership of this bitset.
	InitialHaveDatagrams *bitset.BitSet

	// Multicast of datagrams that we now are allowed to read.
	NewAvailableDatagrams *dchan.Multicast[uint]

	// Channel that is closed when the broadcast operation
	// has reconstituted the data.
	DataReady <-chan struct{}

	// Count of data and parity shards.
	NData, NParity uint16
}

type orDecState struct {
	RS  quic.ReceiveStream
	Dec *CombinationDecoder
}

// RunOutgoingRelay starts several background goroutines
// to manage an outgoing breathcast relay.
func RunOutgoingRelay(
	ctx context.Context,
	log *slog.Logger,
	cfg OutgoingRelayConfig,
) {
	// Buffered so that writes in openOutgoingRelayStream don't block.
	dsCh := make(chan orDecState, 1)
	ssCh := make(chan quic.SendStream, 1)
	initialPeerHas := make(chan *bitset.BitSet, 1)

	// Unbuffered because the goroutines need to track sends and receives.
	peerBitsetUpdates := make(chan *bitset.BitSet)

	// Unbuffered so the relayNewDatagrams is aware of when the bitset changes ownership.
	syncRequests := make(chan *bitset.BitSet)
	// Buffered so the return doesn't block.
	syncReturns := make(chan *bitset.BitSet, 1)

	cfg.WG.Add(4)
	go openOutgoingRelayStream(
		ctx,
		log.With("step", "open_stream"),
		cfg,
		dsCh, ssCh, initialPeerHas,
	)
	go receiveRelayBitsetUpdates(
		ctx,
		log.With("step", "receive_bitset_updates"),
		cfg.WG,
		dsCh,
		peerBitsetUpdates,
		uint(cfg.NData+cfg.NParity),
	)
	go relayNewDatagrams(
		ctx,
		log.With("step", "forward_datagrams"),
		cfg.WG,
		initialPeerHas,
		peerBitsetUpdates,
		cfg.Conn,
		cfg.Datagrams,
		cfg.InitialHaveDatagrams,
		cfg.NewAvailableDatagrams,
		cfg.DataReady,
		syncRequests, syncReturns,
	)
	go sendSynchronousChunks(
		ctx,
		log.With("step", "send_sync"),
		cfg.WG,
		ssCh,
		cfg.Datagrams,
		syncRequests, syncReturns,
	)
}

func openOutgoingRelayStream(
	ctx context.Context,
	log *slog.Logger,
	cfg OutgoingRelayConfig,
	dsCh chan<- orDecState,
	ssCh chan<- quic.SendStream,
	initialPeerHas chan<- *bitset.BitSet,
) {
	defer cfg.WG.Done()

	// If anything goes wrong, closing the channel will indicate
	// to the other goroutines that opening the stream failed.
	// If things go right, it's fine because the other goroutines
	// only attempt to read one value, and they correctly handle
	// the case of the channel being closed.
	defer close(dsCh)
	defer close(ssCh)
	defer close(initialPeerHas)

	s, err := OpenStream(ctx, cfg.Conn, OpenStreamConfig{
		// TODO: make these configurable.
		OpenStreamTimeout: 20 * time.Millisecond,
		SendHeaderTimeout: 20 * time.Millisecond,

		ProtocolHeader: cfg.ProtocolHeader,
		AppHeader:      cfg.AppHeader,
	})
	if err != nil {
		log.Info("Failed to open outgoing stream", "err", err)
		return
	}

	// We have to read the initial bitset from the peer
	// before we can do anything else,
	// so capture that here before signaling the other goroutines.
	const receiveBitsetTimeout = 10 * time.Millisecond
	peerHas := bitset.MustNew(uint(cfg.NData + cfg.NParity))

	dec := new(CombinationDecoder)
	if err := dec.ReceiveBitset(s, receiveBitsetTimeout, peerHas); err != nil {
		log.Info(
			"Failed to receive initial bitset acknowledgement to relay stream",
			"err", err,
		)
		// Close the stream on this error, so it doesn't leak.
		if err := s.Close(); err != nil {
			log.Info("Also failed to close stream", "err", err)
		}
		return
	}

	// These channels are buffered, so we don't need to select against them.
	dsCh <- orDecState{
		RS:  s,
		Dec: dec,
	}
	ssCh <- s
	initialPeerHas <- peerHas
}

// receiveRelayBitsetUpdates reads compressed bitset updates
// from the receiveStream sent on rsCh.
// As it deserializes each bitset,
// the that bitset is sent on the peerBitsetUpdates channel.
func receiveRelayBitsetUpdates(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	dsCh <-chan orDecState,
	peerBitsetUpdates chan<- *bitset.BitSet,
	bsSize uint,
) {
	defer wg.Done()

	// Block until the stream is ready.
	var s quic.ReceiveStream
	var dec *CombinationDecoder
	select {
	case <-ctx.Done():
		return
	case x, ok := <-dsCh:
		if !ok {
			// Channel was closed, so just quit.
			return
		}
		s = x.RS
		dec = x.Dec
	}

	// Now, the peer is going to send bitset updates intermittently.
	// First allocate a destination bitset.
	// This is the bitset that we are writing to.
	wbs := bitset.MustNew(bsSize)

	// The protocol is designed to send bitset updates
	// at a significantly higher frequency than every 10ms.
	// Nonetheless this be made configurable.
	const receiveTimeout = 10 * time.Millisecond

	if err := dec.ReceiveBitset(
		s,
		receiveTimeout,
		wbs,
	); err != nil {
		log.Info(
			"Failed to receive first bitset update",
			"err", err,
		)
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
		return
	case peerBitsetUpdates <- rbs:
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
			log.Info(
				"Failed to receive bitset update",
				"err", err,
			)
			return
		}

		wbs, rbs = rbs, wbs
		select {
		case <-ctx.Done():
			return
		case peerBitsetUpdates <- rbs:
			// Okay.
		}
	}
}

// relayNewDatagrams reacts to new datagrams
// that the broadcast operation receives,
// and forwards them to the peer if the peer does not have them.
//
// This goroutine also tracks what datagrams have been sent
// and some recent bitset updates from the peer;
// if a datagram is unacknowledged within two bitset updates,
// that datagram is sent synchronously
// by coordinating with the [sendSynchronousChunks] goroutine.
func relayNewDatagrams(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	initialPeerHas <-chan *bitset.BitSet,
	peerBitsetUpdates <-chan *bitset.BitSet,
	conn quic.Connection,
	datagrams [][]byte,
	haveDatagrams *bitset.BitSet,
	newAvailableDatagrams *dchan.Multicast[uint],
	dataReady <-chan struct{},
	syncOutCh chan<- *bitset.BitSet,
	syncReturnCh <-chan *bitset.BitSet,
) {
	defer wg.Done()

	var peerHas *bitset.BitSet

AWAIT_PEER_HAS:
	for {
		select {
		case <-ctx.Done():
			return
		case x, ok := <-initialPeerHas:
			if !ok {
				return
			}
			peerHas = x
			break AWAIT_PEER_HAS

		case <-newAvailableDatagrams.Ready:
			// Keep our view of the available datagrams updated.
			haveDatagrams.Set(newAvailableDatagrams.Val)
			newAvailableDatagrams = newAvailableDatagrams.Next
		}
	}

	// Now the peer has acknowledged our handshake,
	// and we know which datagrams they already have.
	// Send datagrams for everything we have that they don't.
	sent := haveDatagrams.Difference(peerHas)
	sendExistingDatagrams(log, conn, datagrams, sent)

	// As we observe the first bitset update from the peer,
	// we populate the "sent but missed" bitset,
	// and we promote those into the "missed and never acknowledged" bitset.
	// Datagrams that go unacknowledged for two bitset updates
	// are enqueued to send synchronously.
	missed := bitset.MustNew(sent.Len())
	unacked := bitset.MustNew(sent.Len())

	// The syncing bitset is treated specially.
	// When non-nil, this goroutine owns it and writes to it.
	// When nil, the sendSynchronousChunks owns it.
	syncing := bitset.MustNew(sent.Len())
	needsSync := false

	for {
		// Two special channels here.
		// Whether these channels are nil depends on
		// the current state of synchronizing datagrams.
		var syncOut chan<- *bitset.BitSet
		var syncReturn <-chan *bitset.BitSet

		if syncing == nil {
			syncReturn = syncReturnCh
		} else if needsSync {
			syncOut = syncOutCh
		}

		select {
		case <-ctx.Done():
			return

		case <-dataReady:
			panic("TODO: handle data ready while relaying new datagrams")

		case u := <-peerBitsetUpdates:
			// The peer sent a synchronous update of what chunks it has.

			if u.Any() {
				// Update what the peer actually has.
				peerHas.InPlaceUnion(u)

				// Clear out any bits in the update chain.
				sent.InPlaceDifference(u)
				missed.InPlaceDifference(u)
				unacked.InPlaceDifference(u)

				// Now propagate through the chain.
				if syncing == nil {
					// There is a sync in progress, so missed gets merged in to unacked.
					unacked.InPlaceUnion(missed)

					// The sent bitset is promoted to missing,
					// then sent is cleared.
					sent, missed = missed, sent
					sent.ClearAll()
				} else {
					// No active sync, so we can merge unacked into syncing.
					syncing.InPlaceDifference(u)
					syncing.InPlaceUnion(unacked)

					// And then promotion.
					sent, missed, unacked = unacked, sent, missed
					sent.ClearAll()
				}
			}

			if syncing != nil && syncing.Any() {
				needsSync = true
			}

		case <-newAvailableDatagrams.Ready:
			idx := newAvailableDatagrams.Val
			newAvailableDatagrams = newAvailableDatagrams.Next

			if !peerHas.Test(idx) {
				// Assuming that sending the datagram won't block here.
				// If that assumption is wrong,
				// we can offload sends to a separate worker goroutine.
				if err := conn.SendDatagram(datagrams[idx]); err != nil {
					log.Info(
						"Failed to send new datagram",
						"idx", idx,
						"err", err,
					)
				}
				sent.Set(idx)
			}

		case syncOut <- syncing:
			// If we needed a sync, we give up the syncing bitset for a moment.
			syncing = nil

		case syncing = <-syncReturn:
			// Nothing to do here.
			// Assume the other goroutine already cleared the bitset.
		}
	}
}

// sendExistingDatagrams sends the already-known datagrams
// that the peer does not have,
// immediately after the peer informs us of the chunks they already have
// at the end of the initial handshake.
func sendExistingDatagrams(
	log *slog.Logger,
	conn quic.Connection,
	datagrams [][]byte,
	toSend *bitset.BitSet,
) {
	// TODO: this should randomly iterate the set bits,
	// otherwise we are likely to have redundant sends with other peers.
	nSent := 0
	for u, ok := toSend.NextSet(0); ok; u, ok = toSend.NextSet(u + 1) {
		if (nSent & 7) == 7 {
			// Micro-sleep to give outgoing datagram buffers a chance to flush.
			// Not actually measured, but seems likely to avoid dropped packets.
			time.Sleep(5 * time.Microsecond)
		}

		if err := conn.SendDatagram(datagrams[u]); err != nil {
			// There are a few reasons why sending the datagram could fail.
			// TODO: inspect this error and quit if the connection is closed.
			log.Info(
				"Failed to send existing datagram",
				"idx", u,
				"err", err,
			)
		}

		nSent++
	}
}

// sendSynchronousChunks coordinates with [relayNewDatagrams]
// to synchronously send datagrams that have gone unacknowledged for too long.
//
// It accepts a bitset indicating which datagrams to send synchronously
// over syncRequestsCh, then sends those datagrams,
// and finally sends the bitset back to the other goroutine
// over syncReturnsCh so that ownership is easily tracked.
func sendSynchronousChunks(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	ssCh <-chan quic.SendStream,
	datagrams [][]byte,
	syncRequestsCh <-chan *bitset.BitSet,
	syncReturnsCh chan<- *bitset.BitSet,
) {
	defer wg.Done()

	var s quic.SendStream
	select {
	case <-ctx.Done():
		return
	case x, ok := <-ssCh:
		if !ok {
			return
		}
		s = x
	}

	for {
		select {
		case <-ctx.Done():
			return

		case req := <-syncRequestsCh:
			var meta [4]byte
			for u, ok := req.NextSet(0); ok; u, ok = req.NextSet(u + 1) {
				const timeout = 3 * time.Millisecond // TODO: make configurable.
				if err := s.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
					panic(fmt.Errorf("TODO: handle error setting write deadline: %w", err))
				}

				// Metadata for the chunk first.
				// The chunk index and the size of the datagram.
				binary.BigEndian.PutUint16(meta[:2], uint16(u))
				binary.BigEndian.PutUint16(meta[2:], uint16(len(datagrams[u])))
				if _, err := s.Write(meta[:]); err != nil {
					panic(fmt.Errorf("TODO: handle error writing sync datagram: %w", err))
				}

				if _, err := s.Write(datagrams[u]); err != nil {
					panic(fmt.Errorf("TODO: handle error writing sync datagram: %w", err))
				}
			}

			// We sent all the synchronous datagrams,
			// so now we have to return the bitset.
			// The channel is buffered, and this goroutine is the only writer,
			// so we don't need a select here.
			syncReturnsCh <- req
		}
	}
}
