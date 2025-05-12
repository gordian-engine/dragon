package bci

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/quic-go/quic-go"
)

// OriginationConfig is the configuration for [RunOrigination].
type OriginationConfig struct {
	// The wait group lives outside the origination.
	WG *sync.WaitGroup

	// The connection on which we will open the stream.
	Conn quic.Connection

	// The protocol header that indicates the specific broadcast operation.
	ProtocolHeader ProtocolHeader

	AppHeader []byte

	// Read-only view of the full set of datagrams.
	Datagrams [][]byte
}

// sendDatagramState is the set of initial values required for [sendDatagrams],
// and it is created in [openOriginationStream].
type sendDatagramState struct {
	Stream  quic.SendStream
	PeerHas *bitset.BitSet
}

// RunOrigination starts several background goroutines
// to manage sending an origination to a single peer.
func RunOrigination(
	ctx context.Context,
	log *slog.Logger,
	cfg OriginationConfig,
) {
	// Buffered so the openOriginationStream work does not block.
	bsdCh := make(chan bsdState, 1)
	sdsCh := make(chan sendDatagramState, 1)

	peerHasDeltaCh := make(chan *bitset.BitSet)
	clearDeltaTimeout := make(chan struct{})

	cfg.WG.Add(3)
	go openOriginationStream(
		ctx,
		log.With("step", "open_origination_stream"),
		cfg.WG,
		cfg.Conn,
		cfg.ProtocolHeader,
		cfg.AppHeader,
		cfg.Datagrams,
		bsdCh,
		sdsCh,
	)
	go sendDatagrams(
		ctx,
		log.With("step", "send_datagrams"),
		cfg.WG,
		cfg.Conn,
		cfg.Datagrams,
		sdsCh,
		peerHasDeltaCh,
		clearDeltaTimeout,
	)
	go receiveBitsetDeltas(
		ctx,
		cfg.WG,
		uint(len(cfg.Datagrams)),
		5*time.Millisecond, // TODO: make configurable
		func(string, error) {
			// TODO: cancel the whole stream here, I think.
		},
		bsdCh,
		peerHasDeltaCh,
		clearDeltaTimeout,
	)
}

// openOriginationStream opens a new stream over the given connection
// in order to receive bitset updates from the peer
// and to send any missed datagrams to the peer.
func openOriginationStream(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	conn quic.Connection,
	pHeader ProtocolHeader,
	appHeader []byte,
	datagrams [][]byte,
	bsdCh chan<- bsdState,
	sdsCh chan<- sendDatagramState,
) {
	defer wg.Done()

	defer close(sdsCh)

	s, err := OpenStream(ctx, conn, OpenStreamConfig{
		// TODO: make these configurable.
		OpenStreamTimeout: 20 * time.Millisecond,
		SendHeaderTimeout: 20 * time.Millisecond,

		ProtocolHeader: pHeader,
		AppHeader:      appHeader,
	})
	if err != nil {
		panic(fmt.Errorf(
			"TODO: handle error opening origination stream: %w", err,
		))
	}

	// We could let the bitset receiving goroutine accept the first bitset,
	// but this goroutine is blocked on that work anyway,
	// so just receive it here.
	peerHas := bitset.MustNew(uint(len(datagrams)))
	dec := new(CombinationDecoder)

	if err := dec.ReceiveBitset(
		s,
		10*time.Millisecond,
		peerHas,
	); err != nil {
		log.Info(
			"Failed to receive initial bitset acknowledgement to origination stream",
			"err", err,
		)
		return
	}

	// Now unblock the other goroutines.
	// These channels are all buffered,
	// so we don't need to select against them.

	bsdCh <- bsdState{
		Stream: s,
		Dec:    dec,
	}

	sdsCh <- sendDatagramState{
		Stream:  s,
		PeerHas: peerHas,
	}
}

// sendDatagrams handles the write side of the stream.
func sendDatagrams(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	conn quic.Connection,
	datagrams [][]byte,
	initialStateCh <-chan sendDatagramState,
	peerHasDeltaCh <-chan *bitset.BitSet,
	clearDeltaTimeout chan<- struct{},
) {
	defer wg.Done()

	var peerHas *bitset.BitSet
	var s quic.SendStream
	select {
	case <-ctx.Done():
		return
	case x, ok := <-initialStateCh:
		if !ok {
			return
		}
		s = x.Stream
		peerHas = x.PeerHas
	}

	// Make a non-nil timer to share with sendUnreliableDatagrams
	// and to also use here.
	timer := time.NewTimer(time.Hour) // Arbitrarily long so it doesn't fire before Stop.
	timer.Stop()

	sendUnreliableDatagrams(
		conn, datagrams, peerHas, peerHasDeltaCh, timer,
	)

	// Indicate that we are done with the unreliable datagrams.
	const sendCompletionTimeout = 20 * time.Millisecond // TODO: make configurable.
	if err := s.SetWriteDeadline(time.Now().Add(sendCompletionTimeout)); err != nil {
		log.Info(
			"Failed to set write deadline for completion",
			"err", err,
		)
		return
	}
	if _, err := s.Write([]byte{datagramsFinishedMessageID}); err != nil {
		log.Info(
			"Failed to write completion indicator",
			"err", err,
		)
		return
	}

	// Now we have to wait for one more bitset update.
	// It is possible that there are multiple bitset updates on the way,
	// but if we receive another one in the middle of sync updates,
	// we will adjust accordingly anyway.
	const finalBitsetWaitTimeout = 100 * time.Millisecond // TODO: make configurable.
	timer.Reset(finalBitsetWaitTimeout)

	select {
	case <-ctx.Done():
		timer.Stop()
		log.Info(
			"Context canceled while waiting for final bitset update",
			"cause", context.Cause(ctx),
		)
		return
	case <-timer.C:
		log.Info("Timed out waiting for final bitset update")
		return
	case u := <-peerHasDeltaCh:
		timer.Stop()
		peerHas.InPlaceUnion(u)
	}

	// Now that we've gotten a final bitset,
	// let the other goroutine know we don't have a deadline
	// for futher delta bitsets.
	close(clearDeltaTimeout)

	if err := sendSyncDatagrams(
		s, datagrams, peerHas, peerHasDeltaCh,
	); err != nil {
		log.Info(
			"Failure when sending synchronous datagrams",
			"err", err,
		)
		return
	}

	// We've sent everything successfully,
	// so now we can close the write side.
	// The quic-go docs make it look like the Close method
	// is a clean close that allows previously written data to finish sending.
	if err := s.Close(); err != nil {
		log.Info("Failed to close stream", "err", err)
	}

	// TODO: need to somehow signal that we are no longer accepting reads either.
}

// sendUnreliableDatagrams sends all the missing datagrams to the peer,
// respecting the peerHas bitset and respecting delta updates
// sent over the peerHasDeltaCh channel.
func sendUnreliableDatagrams(
	conn quic.Connection,
	datagrams [][]byte,
	peerHas *bitset.BitSet,
	peerHasDeltaCh <-chan *bitset.BitSet,
	delay *time.Timer,
) {
	nSent := 0
	const timeout = 2 * time.Microsecond // Arbitrarily chosen.
	for cb := range RandomClearBitIterator(peerHas) {
		// Whether we need to skip this bit due to a new update.
		skip := false

		// Every iteration, check for an update.
		if nSent&7 == 7 {
			// But every 8th iteration, include a sleep.
			delay.Reset(timeout)
		DELAY:
			for {
				select {
				case d := <-peerHasDeltaCh:
					cb.InPlaceUnion(d)
					peerHas.InPlaceUnion(d)
					if !skip {
						skip = peerHas.Test(cb.Idx)
					}
					continue DELAY
				case <-delay.C:
					break DELAY
				}
			}
		} else {
			select {
			case d := <-peerHasDeltaCh:
				cb.InPlaceUnion(d)
				peerHas.InPlaceUnion(d)
				if !skip {
					skip = peerHas.Test(cb.Idx)
				}
			default:
				// Nothing.
			}
		}

		// We will just ignore errors here for now.
		// Although we should probably at least respect connection closed errors.
		if !skip {
			_ = conn.SendDatagram(datagrams[cb.Idx])
		}

		// Increment counter regardless of skip,
		// as we don't want to inadvertently sleep repeatedly.
		nSent++
	}
}

// sendSyncDatagrams inspects the cleared bits in peerHas
// and sends synchronous datagrams to the peer over the given stream.
//
// Delta updates sent over the peerHasDeltaCh are checked
// between individual sends.
func sendSyncDatagrams(
	s quic.SendStream,
	datagrams [][]byte,
	peerHas *bitset.BitSet,
	peerHasDeltaCh <-chan *bitset.BitSet,
) error {
	const sendSyncDatagramTimeout = time.Millisecond // TODO: make configurable.
	for cb := range RandomClearBitIterator(peerHas) {
		// Each iteration, check if there is an updated delta.
		select {
		case d := <-peerHasDeltaCh:
			cb.InPlaceUnion(d)
			peerHas.InPlaceUnion(d)

			// It is possible that we just got the bit we were about to send.
			if peerHas.Test(cb.Idx) {
				continue
			}
		default:
			// Nothing.
		}

		if err := SendSyncDatagram(
			s, sendSyncDatagramTimeout, uint16(cb.Idx), datagrams[cb.Idx],
		); err != nil {
			return fmt.Errorf("failed to send synchronous datagram: %w", err)
		}

		// TODO: we should do some counting in here
		// to avoid sending more datagrams than necessary for the remote
		// to reconstruct the full data.
	}

	return nil
}
