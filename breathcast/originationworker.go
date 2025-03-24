package breathcast

import (
	"context"
	"encoding/binary"
	"log/slog"
	"time"
)

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

	// TODO: accept origination acknowledgement.
}

func (w *originationWorker) handleOriginationError(e error) {
	// TODO: this needs to either directly close the connection,
	// or it needs to feed back to somewhere else indicating we need to close.
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
