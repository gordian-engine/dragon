package breathcast

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"
)

type relayWorker struct {
	log *slog.Logger

	op *RelayOperation
}

// run is the main loop for a relayWorker.
// It is not intended to be called directly,
// but rather is the terminal state of other methods
// like [*relayWorker.AcceptBroadcastFromEmpty].
func (w *relayWorker) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		}
	}
}

// AcceptBroadcastFromEmpty handles a new broadcast message,
// responding that we have no shards yet.
func (w *relayWorker) AcceptBroadcastFromEmpty(ctx context.Context, s quic.Stream) {
	defer w.op.workerWG.Done()

	if err := s.SetWriteDeadline(time.Now().Add(w.op.ackTimeout)); err != nil {
		w.handleStreamError(fmt.Errorf("failed to set write deadline before sending ack: %w", err))
		return
	}

	// This is a fixed response in this method;
	// we have no existing chunks, so we indicate as much to the sender.
	if _, err := s.Write([]byte{0}); err != nil {
		w.handleStreamError(fmt.Errorf("failed to write have-nothing acknowledgement: %w", err))
		return
	}

	// Now we wait as long as necessary to receive the finished confirmation,
	// while the remote is sending us datagrams in the background.
	//
	// It might be better to put a reasonable timeout on this.
	//
	// And in fact this may need to move to its own goroutine,
	// so that the primary goroutine here can go into w.run
	// while we wait for the confirmation.
	if err := s.SetReadDeadline(time.Time{}); err != nil {
		w.handleStreamError(fmt.Errorf("failed to clear read deadline waiting for finish confirmation: %w", err))
		return
	}

	var buf [1]byte
	if _, err := io.ReadFull(s, buf[:]); err != nil {
		w.handleStreamError(fmt.Errorf("failed to read finish confirmation byte: %w", err))
		return
	}

	if buf[0] != originationCompletion {
		w.handleStreamError(fmt.Errorf(
			"expected 0x%x finish confirmation byte, got 0x%x",
			originationCompletion, buf[0],
		))
		return
	}

	// TODO:
	// Now that the sender has finished the unreliable sends,
	// we have to tell the sender what we still need.

	// Standard processing now.
	w.run(ctx)
}

func (w *relayWorker) handleStreamError(e error) {
	// TODO: this should feed back up somewhere to close the stream,
	// and possibly close the connection too.
	w.log.Warn("Error when handling stream", "err", e)
}
