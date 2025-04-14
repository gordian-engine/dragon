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

// outgoingBroadcast manages a broadcast to a peer,
// where we have the full data and the peer doesn't.
type outgoingBroadcast struct {
	log *slog.Logger

	op *BroadcastOperation
}

func (o *outgoingBroadcast) Run(
	ctx context.Context,
	conn quic.Connection,
	protoHeader [4]byte,
) {
	defer o.op.wg.Done()

	const openStreamTimeout = 20 * time.Millisecond // TODO: make configurable.
	openCtx, cancel := context.WithTimeout(ctx, openStreamTimeout)
	s, err := conn.OpenStreamSync(openCtx)
	cancel()
	if err != nil {
		o.log.Info("Failed to open stream", "err", err)
		o.handleError(err)
		return
	}

	const sendHeaderTimeout = 20 * time.Millisecond // TODO: make configurable.
	if err := s.SetWriteDeadline(time.Now().Add(sendHeaderTimeout)); err != nil {
		o.log.Info(
			"Failed to set write deadline for outgoing broadcast stream",
			"err", err,
		)
		o.handleError(err)
		return
	}

	if _, err := s.Write(protoHeader[:]); err != nil {
		o.log.Info(
			"Failed to write protocol header for outgoing broadcast stream",
			"err", err,
		)
		o.handleError(err)
		return
	}

	// Then the actual application header data.
	// Still using the previous write deadline.
	if _, err := s.Write(o.op.appHeader); err != nil {
		o.log.Info(
			"Failed to write application header for outgoing broadcast stream",
			"err", err,
		)
		o.handleError(err)
		return
	}

	// We're going to need a bit set to know which datagrams to send.
	// Allocate it before dealing with the read deadline,
	// so that a slow allocation during GC doesn't eat into that deadline.
	needDatagrams := bitset.MustNew(uint(len(o.op.datagrams)))

	const receiveAckTimeout = 20 * time.Millisecond // TODO: make configurable.
	if err := s.SetReadDeadline(time.Now().Add(receiveAckTimeout)); err != nil {
		o.log.Info(
			"Failed to set read deadline for outgoing broadcast stream",
			"err", err,
		)
		o.handleError(err)
		return
	}

	if err := o.receiveInitialAck(s, needDatagrams); err != nil {
		o.log.Info(
			"Failed to receive initial acknowledgement to origination stream",
			"err", err,
		)
		o.handleError(err)
		return
	}

	if err := o.sendDatagrams(s.Context(), conn, needDatagrams); err != nil {
		o.log.Info(
			"Failed to send datagrams",
			"err", err,
		)
		o.handleError(err)
		return
	}

	// Note that datagrams have been sent.
	const sendCompletionTimeout = 20 * time.Millisecond // TODO: make configurable.
	if err := s.SetWriteDeadline(time.Now().Add(sendCompletionTimeout)); err != nil {
		o.log.Info(
			"Failed to set write deadline for completion",
			"err", err,
		)
		o.handleError(err)
		return
	}

	if _, err := s.Write([]byte{originationCompletion}); err != nil {
		o.log.Info(
			"Failed to write completion indicator",
			"err", err,
		)
		o.handleError(err)
		return
	}

	peerHas, err := o.receiveBitset(s)
	if err != nil {
		o.log.Info("Failed to receive bitset", "err", err)
		o.handleError(err)
		return
	}

	// TODO: iterate over cleared bits in peerHas,
	// and send back the chunks over the reliable stream.
	_ = peerHas
}

func (o *outgoingBroadcast) handleError(e error) {
}

// receiveInitialAck accepts the initial acknowledgement from the peer.
func (o *outgoingBroadcast) receiveInitialAck(
	s quic.Stream, needDatagrams *bitset.BitSet,
) error {
	// Read the single byte indicator first.
	var ackType [1]byte
	if _, err := io.ReadFull(s, ackType[:]); err != nil {
		return fmt.Errorf("failed to read ack type byte: %w", err)
	}

	switch ackType[0] {
	case 0:
		// Peer has nothing.
		// We know the bitset is all clear and is already the correct length.
		needDatagrams.FlipRange(0, needDatagrams.Len())
		return nil
	default:
		// We are going to eventually support other types.
		panic(fmt.Errorf(
			"TODO: handle non-zero ack type (got %x)", ackType[0],
		))
	}
}

func (o *outgoingBroadcast) sendDatagrams(
	streamCtx context.Context, conn quic.Connection,
	needDatagrams *bitset.BitSet,
) error {
	// TODO: we should be able to accept a strategy for how datagrams are sent.
	// We should expect different throttling needs, for instance.
	// There could also be other QoS concerns about datagram order.
	//
	// Until we support a strategy for this, we'll just send the chunks in order.
	// Although, a shuffled order would probably be better for network distribution.

	// How many chunks we have sent so far.
	// Counter for injecting short sleeps every so often.
	var n uint

	for i, dg := range o.op.datagrams {
		if !needDatagrams.Test(uint(i)) {
			continue
		}

		if (n & 7) == 7 {
			// Short sleep for a chance outgoing network buffer to catch up.
			select {
			case <-streamCtx.Done():
				return fmt.Errorf(
					"stream context canceled while sending datagrams: %w",
					context.Cause(streamCtx),
				)
			case <-time.After(time.Microsecond):
				// Okay.
			}
		}

		if err := conn.SendDatagram(dg); err != nil {
			return fmt.Errorf("failed to send datagram: %w", err)
		}

		n++
	}

	return nil
}

// receiveBitset waits for and receives a serialized bitset
// from the peer, after we have notified the peer
// that we have finished sending datagrams.
func (o *outgoingBroadcast) receiveBitset(
	s quic.Stream,
) (*bitset.BitSet, error) {
	// The peer must send us their compressed bitset.
	// There is a 4-byte header first:
	// uint16 for the number of set bits,
	// and another uint16 for the number of bytes for the combination index.
	var meta [4]byte

	const bitsetTimeout = 50 * time.Millisecond // TODO: make this configurable.
	if err := s.SetReadDeadline(time.Now().Add(bitsetTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline for compressed bitset: %w", err)
	}
	if _, err := io.ReadFull(s, meta[:]); err != nil {
		return nil, fmt.Errorf("failed to set read bitset metadata: %w", err)
	}

	k := binary.BigEndian.Uint16(meta[:2])
	combIdxSize := binary.BigEndian.Uint16(meta[2:])

	combBytes := make([]byte, combIdxSize)
	if _, err := io.ReadFull(s, combBytes); err != nil {
		return nil, fmt.Errorf("failed to set read bitset data: %w", err)
	}
	var combIdx big.Int
	combIdx.SetBytes(combBytes)

	var peerHas bitset.BitSet
	n := len(o.op.datagrams)
	decodeCombinationIndex(n, int(k), &combIdx, &peerHas)

	return &peerHas, nil
}
