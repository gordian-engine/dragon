package bci

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dbitset"
	"github.com/quic-go/quic-go"
)

// OriginationConfig is the configuration for [RunOrigination].
type OriginationConfig struct {
	// The wait group lives outside the origination.
	WG *sync.WaitGroup

	// The connection on which we will open the stream.
	Conn dquic.Conn

	// The protocol header that indicates the specific broadcast operation.
	ProtocolHeader ProtocolHeader

	AppHeader []byte

	// Read-only view of the full set of packets.
	Packets [][]byte

	// Required to limit number of reliable chunks sent.
	NData uint16
}

// initialOriginationState is the set of initial values
// required for [sendOriginationPackets],
// and it is created in [openOriginationStream].
type initialOriginationState struct {
	Stream  dquic.SendStream
	PeerHas *bitset.BitSet
}

// RunOrigination starts several background goroutines
// to manage sending an origination to a single peer.
func RunOrigination(
	ctx context.Context,
	log *slog.Logger,
	cfg OriginationConfig,
) {
	if cfg.NData == 0 {
		panic(errors.New("BUG: OriginationConfig.NData must not be zero"))
	}

	// Buffered so the openOriginationStream work does not block.
	bsdCh := make(chan bsdState, 1)
	iosCh := make(chan initialOriginationState, 1)

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
		cfg.Packets,
		bsdCh,
		iosCh,
	)
	go sendOriginationPackets(
		ctx,
		log.With("step", "send_origination_packets"),
		cfg.WG,
		cfg.Conn,
		cfg.Packets,
		cfg.NData,
		iosCh,
		peerHasDeltaCh,
		clearDeltaTimeout,
	)
	go receiveBitsetDeltas(
		ctx,
		cfg.WG,
		uint(len(cfg.Packets)),
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
	conn dquic.Conn,
	pHeader ProtocolHeader,
	appHeader []byte,
	packets [][]byte,
	bsdCh chan<- bsdState,
	iosCh chan<- initialOriginationState,
) {
	defer wg.Done()

	defer close(iosCh)

	s, err := OpenStream(ctx, conn, OpenStreamConfig{
		// TODO: make these configurable.
		OpenStreamTimeout: 20 * time.Millisecond,
		SendHeaderTimeout: 20 * time.Millisecond,

		ProtocolHeader: pHeader,
		AppHeader:      appHeader,

		// In origination we already have 100% of the data.
		Ratio: 0xFF,
	})
	if err != nil {
		log.Info(
			"Failed to open origination stream",
			"err", err,
		)
		return
	}

	// We could let the bitset receiving goroutine accept the first bitset,
	// but this goroutine is blocked on that work anyway,
	// so just receive it here.
	peerHas := bitset.MustNew(uint(len(packets)))
	dec := new(dbitset.AdaptiveDecoder)

	// I would prefer the timeout for receiving the bitset to be lower,
	// but at 10 milliseconds the broadcast integration test
	// fails unacceptably frequently.
	// I don't yet have an explanation on why
	// the first bitset receive would possibly take that long.
	const receiveBitsetTimeout = 20 * time.Millisecond

	if err := dec.ReceiveBitset(
		s,
		receiveBitsetTimeout,
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

	iosCh <- initialOriginationState{
		Stream:  s,
		PeerHas: peerHas,
	}
}

// sendOriginationPackets handles the write side of an origination,
// sending packets as unreliable datagrams first
// and then falling back to a synchronous stream.
func sendOriginationPackets(
	ctx context.Context,
	log *slog.Logger,
	wg *sync.WaitGroup,
	conn dquic.Conn,
	packets [][]byte,
	nData uint16,
	initialStateCh <-chan initialOriginationState,
	peerHasDeltaCh <-chan *bitset.BitSet,
	clearDeltaTimeout chan<- struct{},
) {
	defer wg.Done()

	var peerHas *bitset.BitSet
	var s dquic.SendStream
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
		conn, packets, nil, peerHas, peerHasDeltaCh, timer,
	)

	synchronizeMissedPackets(
		ctx, log,
		s,
		peerHas, peerHasDeltaCh,
		packets, nData,
		timer, clearDeltaTimeout,
	)
}

// synchronizeMissedPackets sends the termination byte on the stream,
// waits for one more bitset delta update,
// and then sends enough packets synchronously to give the peer
// sufficient shards to reconstruct the original data.
func synchronizeMissedPackets(
	ctx context.Context,
	log *slog.Logger,
	s dquic.SendStream,
	peerHas *bitset.BitSet,
	peerBitsetUpdates <-chan *bitset.BitSet,
	packets [][]byte,
	nData uint16,
	timer *time.Timer,
	clearDeltaTimeout chan<- struct{},
) {
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
	case u := <-peerBitsetUpdates:
		timer.Stop()
		peerHas.InPlaceUnion(u)
	}

	// Now that we've gotten a final bitset,
	// let the other goroutine know we don't have a deadline
	// for futher delta bitsets.
	close(clearDeltaTimeout)

	if err := sendSyncPackets(
		s, packets, nData, peerHas, peerBitsetUpdates,
	); err != nil {
		var streamErr *quic.StreamError
		if errors.As(err, &streamErr) {
			if dquic.StreamErrorCode(streamErr.ErrorCode) == GotFullDataErrorCode ||
				dquic.StreamErrorCode(streamErr.ErrorCode) == InterruptedErrorCode {
				// Silently stop here.
				return
			}
		}

		log.Info(
			"Failure when sending synchronous packets",
			"err", err,
		)
		return
	}

	// We've sent everything successfully,
	// so now we can close the write side.
	// The quic-go docs make it look like the Close method
	// is a clean close that allows previously written data to finish sending.
	if err := s.Close(); err != nil {
		if !isCloseOfCanceledStreamError(err) {
			log.Info("Failed to close stream", "err", err)
		}
	}

	// TODO: need to somehow signal that we are no longer accepting reads either.
}

// isCloseOfCanceledStreamError reports whether the given error
// is due to calling Close on a stream that has already been canceled.
func isCloseOfCanceledStreamError(e error) bool {
	// As of writing, quic-go does not have a typed error for this,
	// so we have to resort to string checking:
	// https://github.com/quic-go/quic-go/blob/01921ede97c3cdda7adacd4bb1b21826942ac34c/send_stream.go#L408-L410
	return strings.HasPrefix(e.Error(), "close called for canceled stream ")
}

// sendUnreliableDatagrams sends all the missing datagrams to the peer,
// respecting the peerHas bitset and respecting delta updates
// sent over the peerHasDeltaCh channel.
//
// The alreadySent parameter is optional -- used during relay but not origination --
// indicating which datagrams were already sent unreliably,
// but possibly not yet acknowledged.
//
// This function does update peerHas with deltas from peerHasDeltaCh,
// but it does not update alreadySent,
// because that bitset is not longer used after this function.
//
// sendUnreliableDatagrams ensures that the timer is stopped upon return.
func sendUnreliableDatagrams(
	conn dquic.Conn,
	packets [][]byte,
	alreadySent *bitset.BitSet,
	peerHas *bitset.BitSet,
	peerHasDeltaCh <-chan *bitset.BitSet,
	delay *time.Timer,
) {
	nSent := 0
	const timeout = 2 * time.Microsecond // Arbitrarily chosen.
	it := alreadySent
	if it == nil {
		it = peerHas
	}
	for cb := range dbitset.RandomClearBitIterator(it) {
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
			_ = conn.SendDatagram(packets[cb.Idx])
		}

		// Increment counter regardless of skip,
		// as we don't want to inadvertently sleep repeatedly.
		nSent++
	}
}

// sendSyncPackets inspects the cleared bits in peerHas
// and sends synchronous packets to the peer over the given stream.
//
// Delta updates sent over the peerHasDeltaCh are checked
// between individual sends.
func sendSyncPackets(
	s dquic.SendStream,
	packets [][]byte,
	nData uint16,
	peerHas *bitset.BitSet,
	peerHasDeltaCh <-chan *bitset.BitSet,
) error {
	// Track how many packets the peer is missing
	// to be able to reconstruct the data.
	haveCount := peerHas.Count()
	if haveCount >= uint(nData) {
		return nil
	}
	need := nData - uint16(haveCount)

	const sendSyncPacketTimeout = time.Millisecond // TODO: make configurable.
	for cb := range dbitset.RandomClearBitIterator(peerHas) {
		// Each iteration, check if there is an updated delta.
		select {
		case d := <-peerHasDeltaCh:
			cb.InPlaceUnion(d)
			peerHas.InPlaceUnion(d)

			// Recalculate the minimum required count.
			haveCount = peerHas.Count()
			if haveCount >= uint(nData) {
				return nil
			}
			need = nData - uint16(haveCount)

			// It is possible that we just got the bit we were about to send.
			if peerHas.Test(cb.Idx) {
				continue
			}
		default:
			// Nothing.
		}

		if err := SendSyncPacket(
			s, sendSyncPacketTimeout, packets[cb.Idx],
		); err != nil {
			return fmt.Errorf("failed to send synchronous packet: %w", err)
		}

		need--
		if need == 0 {
			return nil
		}
	}

	return nil
}
