package bci

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/internal/dbitset"
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

	// Read-only view of the packets that the operation has available.
	Packets [][]byte

	// What packets we are initially allowed to read.
	// The RunOutgoingRelay function takes ownership of this bitset.
	InitialHavePackets *bitset.BitSet

	// Pubsub stream of indices of packets that we now are allowed to read.
	NewAvailablePackets *dpubsub.Stream[uint]

	// Channel that is closed when the broadcast operation
	// has reconstituted the data.
	DataReady <-chan struct{}

	// Count of data and parity shards.
	NData, NParity uint16
}

// RunOutgoingRelay starts several background goroutines
// to manage an outgoing breathcast relay.
func RunOutgoingRelay(
	ctx context.Context,
	log *slog.Logger,
	cfg OutgoingRelayConfig,
) {
	// Buffered so that writes in openOutgoingRelayStream don't block.
	ssStartCh := make(chan quic.SendStream, 1)
	ssEndCh := make(chan quic.SendStream, 1)
	initialPeerHas := make(chan *bitset.BitSet, 1)
	bsdCh := make(chan bsdState, 1)

	// Unbuffered because the goroutines need to track sends and receives.
	peerBitsetUpdates := make(chan *bitset.BitSet)

	clearDeltaTimeout := make(chan struct{})

	// Unbuffered so the relayNewDatagrams is aware of when the bitset changes ownership.
	syncRequests := make(chan *bitset.BitSet)
	// Buffered so the return doesn't block.
	syncReturns := make(chan *bitset.BitSet, 1)

	cfg.WG.Add(4)
	go openOutgoingRelayStream(
		ctx,
		log.With("step", "open_stream"),
		cfg,
		bsdCh, ssStartCh, initialPeerHas,

		// Have to calculate the ratio here to avoid a read-write data race
		// from relayNewDatagrams writing to the bitset.
		calculateRatio(cfg.InitialHavePackets),
	)
	go receiveBitsetDeltas(
		ctx,
		cfg.WG,
		uint(len(cfg.Packets)),
		10*time.Millisecond, // TODO: make configurable
		func(string, error) {
			// TODO: cancel the whole stream here, I think.
		},
		bsdCh,
		peerBitsetUpdates,
		clearDeltaTimeout,
	)
	go relayNewDatagrams(
		ctx,
		log.With("step", "forward_datagrams"),
		cfg.WG,
		initialPeerHas,
		peerBitsetUpdates,
		cfg.Conn,
		cfg.Packets,
		cfg.NData,
		cfg.InitialHavePackets,
		cfg.NewAvailablePackets,
		cfg.DataReady,
		syncRequests, syncReturns,
		ssEndCh,
		clearDeltaTimeout,
	)
	go sendMissedPackets(
		ctx,
		log.With("step", "send_sync"),
		cfg.WG,
		ssStartCh,
		ssEndCh,
		cfg.Packets,
		syncRequests, syncReturns,
	)
}

func openOutgoingRelayStream(
	ctx context.Context,
	log *slog.Logger,
	cfg OutgoingRelayConfig,
	bsdCh chan<- bsdState,
	ssCh chan<- quic.SendStream,
	initialPeerHas chan<- *bitset.BitSet,
	haveRatio byte,
) {
	defer cfg.WG.Done()

	// If anything goes wrong, closing the channel will indicate
	// to the other goroutines that opening the stream failed.
	// If things go right, it's fine because the other goroutines
	// only attempt to read one value, and they correctly handle
	// the case of the channel being closed.
	defer close(bsdCh)
	defer close(ssCh)
	defer close(initialPeerHas)

	s, err := OpenStream(ctx, cfg.Conn, OpenStreamConfig{
		// TODO: make these configurable.
		OpenStreamTimeout: 20 * time.Millisecond,
		SendHeaderTimeout: 20 * time.Millisecond,

		ProtocolHeader: cfg.ProtocolHeader,
		AppHeader:      cfg.AppHeader,

		Ratio: haveRatio,
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

	dec := new(dbitset.AdaptiveDecoder)
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
	bsdCh <- bsdState{
		Stream: s,
		Dec:    dec,
	}
	ssCh <- s
	initialPeerHas <- peerHas
}

// relayNewDatagrams reacts to new datagrams
// that the broadcast operation receives,
// and forwards them to the peer if the peer does not have them.
//
// This goroutine also tracks what datagrams have been sent
// and some recent bitset updates from the peer;
// if a datagram is unacknowledged within two bitset updates,
// that packet is sent synchronously
// by coordinating with the [sendMissedPackets] goroutine.
func relayNewDatagrams(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	initialPeerHas <-chan *bitset.BitSet,
	peerBitsetUpdates <-chan *bitset.BitSet,
	conn quic.Connection,
	packets [][]byte,
	nData uint16,
	havePackets *bitset.BitSet,
	newAvailablePackets *dpubsub.Stream[uint],
	dataReady <-chan struct{},
	syncOutCh chan<- *bitset.BitSet,
	syncReturnCh <-chan *bitset.BitSet,
	ssEndCh <-chan quic.SendStream,
	clearDeltaTimeout chan<- struct{},
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

		case <-newAvailablePackets.Ready:
			// Keep our view of the available packets updated.
			havePackets.Set(newAvailablePackets.Val)
			newAvailablePackets = newAvailablePackets.Next
		}
	}

	// Now the peer has acknowledged our handshake,
	// and we know which packets they already have.
	// Send datagrams for everything we have that they don't.
	sent := havePackets.Difference(peerHas)
	sendExistingDatagrams(log, conn, packets, sent)

	// The missed bitset indicates which datagrams we sent
	// and were absent from at least one peer delta update.
	missed := bitset.MustNew(sent.Len())

	// The syncing bitset is treated specially.
	// When non-nil, this goroutine owns it and writes to it.
	// When nil, the sendMissedPackets owns it.
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
			// We didn't have the full set of data, and now we do.

			// Closing this channel indicates we are not going to
			// request any further syncs, so that goroutine can stop.
			close(syncOutCh)

			sent.InPlaceUnion(peerHas)
			sent.InPlaceUnion(missed)
			if syncing != nil {
				sent.InPlaceUnion(syncing)
			}
			finishRelay(
				ctx, log,
				conn,
				ssEndCh,
				peerHas, peerBitsetUpdates,
				packets,
				sent,
				nData,
				clearDeltaTimeout,
			)
			return

		case u := <-peerBitsetUpdates:
			// The peer sent a synchronous update of what chunks it has.

			if u.Any() {
				// Update what the peer actually has.
				peerHas.InPlaceUnion(u)

				// Clear out any bits in the update chain.
				sent.InPlaceDifference(u)
				missed.InPlaceDifference(u)
			}

			// Now propagate through the chain.
			if syncing == nil {
				// There is a sync in progress, so we can't promote missed.
				missed.InPlaceUnion(sent)
				sent.ClearAll()
			} else {
				// No active sync, so we can merge missed into syncing.
				syncing.InPlaceDifference(u)
				syncing.InPlaceUnion(missed)

				// And then promotion.
				sent, missed = missed, sent
				sent.ClearAll()
			}

			if syncing != nil && syncing.Any() {
				needsSync = true
			}

		case <-newAvailablePackets.Ready:
			idx := newAvailablePackets.Val
			newAvailablePackets = newAvailablePackets.Next

			if !peerHas.Test(idx) {
				// Assuming that sending the datagram won't block here.
				// If that assumption is wrong,
				// we can offload sends to a separate worker goroutine.
				if err := conn.SendDatagram(packets[idx]); err != nil {
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
			needsSync = false

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
	packets [][]byte,
	toSend *bitset.BitSet,
) {
	nSent := 0
	for sb := range dbitset.RandomSetBitIterator(toSend) {
		if (nSent & 7) == 7 {
			// Micro-sleep to give outgoing datagram buffers a chance to flush.
			// Not actually measured, but seems likely to avoid dropped packets.
			time.Sleep(5 * time.Microsecond)
		}

		if err := conn.SendDatagram(packets[sb.Idx]); err != nil {
			// There are a few reasons why sending the datagram could fail.
			// TODO: inspect this error and quit if the connection is closed.
			log.Info(
				"Failed to send existing datagram",
				"idx", sb.Idx,
				"err", err,
			)
		}

		nSent++
	}
}

// sendMissedPackets coordinates with [relayNewDatagrams]
// to synchronously send packets that have gone unacknowledged for too long.
//
// It accepts a bitset indicating which packets to send synchronously
// over syncRequestsCh, then sends those packets,
// and finally sends the bitset back to the other goroutine
// over syncReturnsCh so that ownership is easily tracked.
func sendMissedPackets(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	ssInCh <-chan quic.SendStream,
	ssOutCh chan<- quic.SendStream,
	packets [][]byte,
	syncRequestsCh <-chan *bitset.BitSet,
	syncReturnsCh chan<- *bitset.BitSet,
) {
	defer wg.Done()
	defer close(ssOutCh)

	var s quic.SendStream
	select {
	case <-ctx.Done():
		return
	case x, ok := <-ssInCh:
		if !ok {
			return
		}
		s = x
	}

	for {
		select {
		case <-ctx.Done():
			return

		case req, ok := <-syncRequestsCh:
			if !ok {
				// Channel closed means no further work for this goroutine.
				// Give up control of the steam now.
				ssOutCh <- s // Output channel was buffered already.
				return
			}

			for sb := range dbitset.RandomSetBitIterator(req) {
				const timeout = 3 * time.Millisecond // TODO: make configurable.
				SendSyncMissedDatagram(s, timeout, packets[sb.Idx])
			}

			// We sent all the synchronous packets,
			// so now we have to return the bitset.
			// The channel is buffered, and this goroutine is the only writer,
			// so we don't need a select here.
			// We clear the bitset first here,
			// since the other goroutine is more likely to be contended.
			req.ClearAll()
			syncReturnsCh <- req
		}
	}
}

// finishRelay handles remaining work on the stream,
// changing behavior from relaying incoming data
// to effectively broadcasting any remaining data for the peer.
func finishRelay(
	ctx context.Context,
	log *slog.Logger,
	conn quic.Connection,
	sCh <-chan quic.SendStream,
	peerHas *bitset.BitSet,
	peerBitsetUpdates <-chan *bitset.BitSet,
	packets [][]byte,
	alreadySent *bitset.BitSet,
	nData uint16,
	clearDeltaTimeout chan<- struct{},
) {
	// Make a timer to share with sendUnreliableDatagrams
	// and to also use here.
	timer := time.NewTimer(time.Hour)
	timer.Stop()

	sendUnreliableDatagrams(
		conn, packets, alreadySent, peerHas, peerBitsetUpdates, timer,
	)

	// Now that we've sent the datagrams that we haven't sent before,
	// we need to send the termination byte.
	// But to do that, we need to control the stream again.
	// Prior to calling this function,
	// we closed the synchronization request channel,
	// which signaled to [sendMissedPackets]
	// that it needs to return the stream over the sCh channel.
	var s quic.SendStream
AWAIT_STREAM_CONTROL:
	for {
		var ok bool
		select {
		case <-ctx.Done():
			return
		case s, ok = <-sCh:
			if !ok {
				// The stream channel closed,
				// indicating that the goroutine sending on that channel
				// had to quit before sending a value.
				// All we can do here is also quit.
				return
			}

			// Otherwise we have a valid stream,
			// so we can advance in this function.
			break AWAIT_STREAM_CONTROL
		case u := <-peerBitsetUpdates:
			peerHas.InPlaceUnion(u)
			continue AWAIT_STREAM_CONTROL
		}
	}

	synchronizeMissedPackets(
		ctx, log,
		s,
		peerHas, peerBitsetUpdates,
		packets, nData,
		timer, clearDeltaTimeout,
	)
}
