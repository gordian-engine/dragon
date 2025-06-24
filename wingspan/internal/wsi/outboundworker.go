package wsi

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
	"github.com/quic-go/quic-go"
)

// OutboundWorker manages the outbound stream
// to a particular peer, for a particular session.
type OutboundWorker[D any] struct {
	log *slog.Logger

	header []byte

	s      wspacket.OutboundRemoteState[D]
	deltas *dchan.Multicast[D]
}

// NewOutboundWorker returns a new OutboundWorker.
func NewOutboundWorker[D any](
	log *slog.Logger,
	header []byte,
	state wspacket.OutboundRemoteState[D],
	deltas *dchan.Multicast[D],
) *OutboundWorker[D] {
	return &OutboundWorker[D]{
		log: log,

		header: header,

		s:      state,
		deltas: deltas,
	}
}

// Run executes the main loop of outbound work.
// It is intended to be run in its own goroutine.
func (w *OutboundWorker[D]) Run(
	ctx context.Context,
	parentWG *sync.WaitGroup,
	conn quic.Connection,
	writeHeaderTimeout time.Duration,
	peerReceivedCh <-chan D,
) {
	defer parentWG.Done()

	s, err := w.initializeStream(ctx, conn, writeHeaderTimeout)
	if err != nil {
		w.log.Info(
			"Failed to initialize outbound session stream",
			"err", err,
		)
		return
	}
	defer func() {
		if err := s.Close(); err != nil {
			w.log.Info("Failed to close stream", "err", err)
		}
	}()

	// Send out whatever we have initially.
	if err := w.sendPackets(ctx, s, peerReceivedCh); err != nil {
		w.log.Info(
			"Error while sending initial packets",
			"err", err,
		)
		return
	}

	// Now wait for any relevant updates before attempting to send again.
	for {
		select {
		case <-ctx.Done():
			return

		case <-w.deltas.Ready:
			if err := w.sendPackets(ctx, s, peerReceivedCh); err != nil {
				w.log.Info(
					"Error while sending packets in main loop",
					"err", err,
				)
				return
			}

		case d := <-peerReceivedCh:
			w.s.AddUnverifiedFromPeer(d)
		}
	}
}

func (w *OutboundWorker[D]) initializeStream(
	ctx context.Context,
	conn quic.Connection,
	writeHeaderTimeout time.Duration,
) (quic.SendStream, error) {
	s, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to open outgoing stream: %w", err,
		)
	}

	if err := s.SetWriteDeadline(time.Now().Add(writeHeaderTimeout)); err != nil {
		return nil, fmt.Errorf(
			"failed to set write deadline: %w", err,
		)
	}

	if _, err := s.Write(w.header); err != nil {
		return nil, fmt.Errorf(
			"failed to write protocol header: %w", err,
		)
	}

	return s, nil
}

func (w *OutboundWorker[D]) sendPackets(
	ctx context.Context,
	s quic.SendStream,
	peerReceivedCh <-chan D,
) error {
	// Make sure local packets are up to date.
UPDATE_PACKET_SET:
	for {
		// Not selecting against context here since this should be nearly non-blocking.
		select {
		case <-w.deltas.Ready:
			val := w.deltas.Val
			w.deltas = w.deltas.Next
			w.s.ApplyUpdateFromCentral(val)
			continue UPDATE_PACKET_SET
		case d := <-peerReceivedCh:
			w.s.AddUnverifiedFromPeer(d)
			continue UPDATE_PACKET_SET
		default:
			break UPDATE_PACKET_SET
		}
	}

	const sendPacketTimeout = 4 * time.Millisecond // TODO: make configurable.

	// Now that our packet set is up to date,
	// send out what we have so far.
	var needsUpdate bool
SEND_PACKETS:
	for p := range w.s.UnsentPackets() {
		if err := s.SetWriteDeadline(time.Now().Add(sendPacketTimeout)); err != nil {
			return fmt.Errorf(
				"failed to set write deadline for sending outbound packet: %w", err,
			)
		}

		if _, err := s.Write(p.Bytes()); err != nil {
			return fmt.Errorf(
				"failed to write packet bytes: %w", err,
			)
		}

		p.MarkSent()

		// After every packet sent,
		// we check if we need to re-sync the packet set.
		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"context canceled between packet sends: %w",
				context.Cause(ctx),
			)
		case <-w.deltas.Ready:
			// Don't actually do the update here,
			// because we are in the middle of using an iterator.
			needsUpdate = true
			break SEND_PACKETS
		case d := <-peerReceivedCh:
			w.s.AddUnverifiedFromPeer(d)
			// We don't need to break iteration on unverified packets.
		default:
			// Nothing, continue iterating the unsent packets.
		}
	}

	if needsUpdate {
		needsUpdate = false
		goto UPDATE_PACKET_SET
	}

	return nil
}
