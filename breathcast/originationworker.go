package breathcast

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/quic-go/quic-go"
)

// After sending all the datagrams of chunks,
// this byte is sent over the reliable channel
// to notify the receiver that they must now request any missing chunks.
const originationCompletion byte = 0xff

// originationWorker manages the work of originating a broadcast
// to the peers in the active view.
type originationWorker struct {
	log *slog.Logger

	cw *connectionWorker
}

func (w *originationWorker) run(o origination) {
	defer w.cw.wg.Done()

	// We are originating a broadcast to the peer on this connection.
	// Open the stream first.

	// We need to synchronously open a stream for this,
	// which means we need to pass a context.
	// Unfortunately at this point we have two independent context values,
	// and OpenStreamSync only accepts one;
	// and there no existing solution in the standard library for merging contexts.
	// So, we start a goroutine to monitor both and manage a derived context.
	// The derived context is canceled if either parent is canceled.
	openStreamCtx, cancel1 := joinTwoContexts(o.Ctx, w.cw.Ctx)

	openStreamCtx, cancel2 := context.WithTimeout(openStreamCtx, o.OpenStreamTimeout)

	s, err := w.cw.QUIC.OpenStreamSync(openStreamCtx)
	// Cancel ASAP to free resources.
	cancel2()
	cancel1()

	if err != nil {
		w.log.Info(
			"Context canceled while opening origination stream",
			"cause", context.Cause(openStreamCtx),
		)
		w.handleOriginationError(err)
		return
	}

	// Now that we have the stream, first we send the stream header.
	if err := s.SetWriteDeadline(time.Now().Add(o.SendHeaderTimeout)); err != nil {
		w.log.Info(
			"Failed to set write deadline for origination stream",
			"err", err,
		)
		w.handleOriginationError(err)
		return
	}

	var protoHeader [4]byte
	// Application-decided protocol ID.
	protoHeader[0] = o.ProtocolID

	// As the broadcast originator, our "have ratio" is 100%.
	protoHeader[1] = 0xFF

	// Then the 16-bit big-endian app header length.
	binary.BigEndian.PutUint16(protoHeader[2:], uint16(len(o.Header)))

	if _, err := s.Write(protoHeader[:]); err != nil {
		w.log.Info(
			"Failed to write protocol header for origination stream",
			"err", err,
		)
		w.handleOriginationError(err)
		return
	}

	// Then the actual header data.
	// Still using the previous write deadline.
	if _, err := s.Write(o.Header); err != nil {
		w.log.Info(
			"Failed to write header for origination stream",
			"err", err,
		)
		w.handleOriginationError(err)
		return
	}

	// We're going to need a bit set to know which datagrams to send.
	// Allocate it before dealing with the read deadline,
	// so that a slow allocation during GC doesn't eat into that deadline.
	needDatagrams := bitset.MustNew(uint(len(o.DataChunks) + len(o.ParityChunks)))

	if err := s.SetReadDeadline(time.Now().Add(o.ReceiveAckTimeout)); err != nil {
		w.log.Info(
			"Failed to set read deadline for origination stream",
			"err", err,
		)
		w.handleOriginationError(err)
		return
	}

	if err := w.receiveInitialAck(s, needDatagrams); err != nil {
		w.log.Info(
			"Failed to receive initial acknowledgement to origination stream",
			"err", err,
		)
		w.handleOriginationError(err)
		return
	}

	if err := w.sendDatagrams(s.Context(), w.cw.QUIC, o, needDatagrams); err != nil {
		w.log.Info(
			"Failed to send datagrams",
			"err", err,
		)
		w.handleOriginationError(err)
		return
	}

	if err := s.SetWriteDeadline(time.Now().Add(o.SendCompletionTimeout)); err != nil {
		w.log.Info(
			"Failed to set write deadline for completion",
			"err", err,
		)
		w.handleOriginationError(err)
		return
	}

	if _, err := s.Write([]byte{originationCompletion}); err != nil {
		w.log.Info(
			"Failed to write completion indicator",
			"err", err,
		)
		w.handleOriginationError(err)
		return
	}

	// TODO: read status from peer, so we know what chunks they still need.
	// We can reuse needDatagrams here.
}

func (w *originationWorker) handleOriginationError(e error) {
	// TODO: this needs to either directly close the connection,
	// or it needs to feed back to somewhere else indicating we need to close.
}

// receiveInitialAck accepts the initial acknowledgement from the peer
// following our origination.
func (w *originationWorker) receiveInitialAck(
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

func (w *originationWorker) sendDatagrams(
	streamCtx context.Context, conn quic.Connection,
	o origination, needDatagrams *bitset.BitSet,
) error {
	// TODO: we should be able to accept a strategy for how datagrams are sent.
	// We should expect different throttling needs, for instance.
	// There could also be other QoS concerns about datagram order.
	//
	// Until we support a strategy for this, we'll just send the chunks in order.

	// How many chunks we have sent so far.
	// Counter for injecting short sleeps every so often.
	var n uint

	for i := range len(o.DataChunks) + len(o.ParityChunks) {
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
			case <-o.Ctx.Done():
				return fmt.Errorf(
					"origination context canceld while sending datagrams: %w",
					context.Cause(o.Ctx),
				)
			case <-time.After(time.Microsecond):
				// Okay.
			}
		}

		var c []byte
		if i < len(o.DataChunks) {
			c = o.DataChunks[i]
		} else {
			c = o.ParityChunks[i-len(o.DataChunks)]
		}

		if err := conn.SendDatagram(c); err != nil {
			return fmt.Errorf("failed to send datagram: %w", err)
		}

		n++
	}

	return nil
}

func joinTwoContexts(ctx1, ctx2 context.Context) (context.Context, context.CancelFunc) {
	// Hopefully nothing depends on any context values,
	// because we are not propagating any at this point.
	ctx, cancel := context.WithCancelCause(context.Background())

	quit := make(chan struct{})

	go func() {
		select {
		case <-quit:
			return
		case <-ctx1.Done():
			cancel(context.Cause(ctx1))
		case <-ctx2.Done():
			cancel(context.Cause(ctx2))
		}
	}()

	return ctx, func() {
		close(quit)
	}
}
