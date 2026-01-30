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

	Timeouts OriginationTimeouts
}

// OriginationTimeouts is a copy of breathcast.OriginationTimeouts.
// We could use an alias but for a small struct that just hurts readability.
type OriginationTimeouts struct {
	// How long to wait for recipient to send initial bitset,
	// and how long to allow between each subsequent bitset.
	ReceiveBitsetTimeout time.Duration

	// When sending datagrams, occasionally add a short pause of this duration
	// to hopefully reduce UDP contention.
	OccasionalDatagramSleep time.Duration

	// After sending the "datagrams finished" message to the peer,
	// how long to allow for the next bitset update
	// (which informs the originator which packets need to be sent synchronously).
	FinalBitsetWaitTimeout time.Duration

	// How long to allow the send of a synchronous packet to be blocked.
	// Both sides of the connection should be configured with gracious buffer space,
	// so it should be okay for this to be a relatively short duration.
	SendSyncPacketTimeout time.Duration
}

// IsZero reports whether t has all zero duration values.
func (t OriginationTimeouts) IsZero() bool {
	return t.ReceiveBitsetTimeout == 0 &&
		t.OccasionalDatagramSleep == 0 &&
		t.FinalBitsetWaitTimeout == 0 &&
		t.SendSyncPacketTimeout == 0
}

func DefaultOriginationTimeouts() OriginationTimeouts {
	return OriginationTimeouts{
		ReceiveBitsetTimeout: 50 * time.Millisecond,

		OccasionalDatagramSleep: 75 * time.Microsecond, // Yes, sub-millisecond.

		FinalBitsetWaitTimeout: 250 * time.Millisecond,

		SendSyncPacketTimeout: 20 * time.Millisecond,
	}
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

	// openOriginationStream sends on these two channels,
	// allowing the other two goroutines to proceed from initial state.
	// On error, openOriginationStream closes the channels without sending,
	// and the other goroutines understand that to be an error state.
	bsdCh := make(chan bsdState, 1)
	iosCh := make(chan initialOriginationState, 1)

	peerHasDeltaCh := make(chan *bitset.BitSet)
	clearDeltaTimeoutCh := make(chan struct{})

	cfg.WG.Add(3)
	go openOriginationStream(
		ctx,
		log.With("step", "open_origination_stream"),
		cfg.WG,
		cfg.Conn,
		cfg.ProtocolHeader,
		cfg.AppHeader,
		cfg.Packets,
		cfg.Timeouts.ReceiveBitsetTimeout,
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
		clearDeltaTimeoutCh,
		cfg.Timeouts.OccasionalDatagramSleep,
		cfg.Timeouts.FinalBitsetWaitTimeout,
		cfg.Timeouts.SendSyncPacketTimeout,
	)
	go receiveBitsetDeltas(
		ctx,
		cfg.WG,
		uint(len(cfg.Packets)),
		cfg.Timeouts.ReceiveBitsetTimeout,
		func(string, error) {
			// TODO: cancel the whole stream here, I think.
		},
		bsdCh,
		peerHasDeltaCh,
		clearDeltaTimeoutCh,
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
	initialReceiveTimeout time.Duration,
	bsdCh chan<- bsdState,
	iosCh chan<- initialOriginationState,
) {
	defer wg.Done()

	defer close(iosCh)
	defer close(bsdCh)

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

	if err := dec.ReceiveBitset(
		s,
		initialReceiveTimeout,
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
	clearDeltaTimeoutCh chan<- struct{},
	occasionalDatagramSleep time.Duration,
	finalBitsetWaitTimeout time.Duration,
	sendSyncPacketTimeout time.Duration,
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

	// Make a non-nil timer to use in both sendUnreliableDatagrams and synchronizeMissedPackets.
	timer := time.NewTimer(time.Hour) // Arbitrarily long so it doesn't fire before Stop.
	timer.Stop()

	sendUnreliableDatagrams(
		conn, packets, nil, peerHas, peerHasDeltaCh, timer, occasionalDatagramSleep,
	)

	synchronizeMissedPackets(
		ctx, log,
		s,
		peerHas, peerHasDeltaCh,
		packets, nData,
		timer, finalBitsetWaitTimeout, sendSyncPacketTimeout,
		clearDeltaTimeoutCh,
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
	finalBitsetWaitTimer *time.Timer,
	finalBitsetWaitTimeout time.Duration,
	sendSyncPacketTimeout time.Duration,
	clearDeltaTimeoutCh chan<- struct{},
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
	finalBitsetWaitTimer.Reset(finalBitsetWaitTimeout)

	select {
	case <-ctx.Done():
		finalBitsetWaitTimer.Stop()
		log.Info(
			"Context canceled while waiting for final bitset update",
			"cause", context.Cause(ctx),
		)
		return
	case <-finalBitsetWaitTimer.C:
		log.Info("Timed out waiting for final bitset update")
		return
	case u := <-peerBitsetUpdates:
		finalBitsetWaitTimer.Stop()
		peerHas.InPlaceUnion(u)
	}

	// Now that we've gotten a final bitset,
	// let the other goroutine know we don't have a deadline
	// for futher delta bitsets.
	close(clearDeltaTimeoutCh)

	if err := sendSyncPackets(
		s, packets, nData, peerHas, peerBitsetUpdates, sendSyncPacketTimeout,
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
	delayTimer *time.Timer,
	occasionalSleepDur time.Duration,
) {
	defer delayTimer.Stop()

	nSent := 0
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
			delayTimer.Reset(occasionalSleepDur)
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
				case <-delayTimer.C:
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
	sendSyncPacketTimeout time.Duration,
) error {
	// Track how many packets the peer is missing
	// to be able to reconstruct the data.
	haveCount := peerHas.Count()
	if haveCount >= uint(nData) {
		return nil
	}
	need := nData - uint16(haveCount)

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

		// Our copy of peerHas must be up to date,
		// because the iterator works on a copy,
		// and we refresh the remaining need count
		// upon receiving a peer delta update.
		peerHas.Set(cb.Idx)
	}

	return nil
}
