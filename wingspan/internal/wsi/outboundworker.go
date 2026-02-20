package wsi

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dtrace"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
)

// OutboundWorker manages the outbound stream
// to a particular peer, for a particular session.
type OutboundWorker[
	PktIn any, PktOut wspacket.OutboundPacket,
	DeltaIn, DeltaOut any,
] struct {
	log *slog.Logger

	tracer dtrace.Tracer

	header []byte

	s      wspacket.OutboundRemoteState[PktIn, PktOut, DeltaIn, DeltaOut]
	deltas *dpubsub.Stream[DeltaOut]
}

// NewOutboundWorker returns a new OutboundWorker.
func NewOutboundWorker[
	PktIn any, PktOut wspacket.OutboundPacket,
	DeltaIn, DeltaOut any,
](
	log *slog.Logger,
	tracer dtrace.Tracer,
	header []byte,
	state wspacket.OutboundRemoteState[PktIn, PktOut, DeltaIn, DeltaOut],
	deltas *dpubsub.Stream[DeltaOut],
) *OutboundWorker[PktIn, PktOut, DeltaIn, DeltaOut] {
	return &OutboundWorker[PktIn, PktOut, DeltaIn, DeltaOut]{
		log: log,

		tracer: tracer,

		header: header,

		s:      state,
		deltas: deltas,
	}
}

// Run executes the main loop of outbound work.
// It is intended to be run in its own goroutine.
func (w *OutboundWorker[PktIn, PktOut, DeltaIn, DeltaOut]) Run(
	ctx context.Context,
	parentWG *sync.WaitGroup,
	conn dquic.Conn,
	openStreamTimeout time.Duration,
	writeHeaderTimeout time.Duration,
	sendPacketTimeout time.Duration,
	peerReceivedCh <-chan DeltaIn,
) {
	defer parentWG.Done()

	ctx, span := w.tracer.Start(
		ctx,
		"outbound worker main loop",
		dtrace.WithAttributes(
			dtrace.RemoteAddrAttr(conn),
		),
	)
	defer span.End()

	span.AddEvent("initialize outbound worker stream")
	s, err := w.initializeStream(ctx, conn, openStreamTimeout, writeHeaderTimeout)
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
	span.AddEvent("send initial outbound packets")
	if err := w.sendPackets(ctx, s, sendPacketTimeout, peerReceivedCh); err != nil {
		w.log.Info(
			"Error while sending initial packets",
			"err", err,
		)
		dtrace.SpanError(span, err)
		return
	}

	// Now wait for any relevant updates before attempting to send again.
	for {
		select {
		case <-ctx.Done():
			return

		case <-w.deltas.Ready:
			span.AddEvent("send updated outbound packets")
			if err := w.sendPackets(ctx, s, sendPacketTimeout, peerReceivedCh); err != nil {
				w.log.Info(
					"Error while sending packets in main loop",
					"err", err,
				)
				dtrace.SpanError(span, err)
				return
			}

		case d := <-peerReceivedCh:
			w.s.AddUnverifiedFromPeer(d)
		}
	}
}

func (w *OutboundWorker[PktIn, PktOut, DeltaIn, DeltaOut]) initializeStream(
	ctx context.Context,
	conn dquic.Conn,
	openStreamTimeout time.Duration,
	writeHeaderTimeout time.Duration,
) (dquic.SendStream, error) {
	openCtx, cancel := context.WithTimeout(ctx, openStreamTimeout)
	s, err := conn.OpenUniStreamSync(openCtx)
	cancel() // Immediately cancel to free context resources.
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

func (w *OutboundWorker[PktIn, PktOut, DeltaIn, DeltaOut]) sendPackets(
	ctx context.Context,
	s dquic.SendStream,
	sendPacketTimeout time.Duration,
	peerReceivedCh <-chan DeltaIn,
) error {
	ctx, span := w.tracer.Start(ctx, "send packets")
	defer span.End()

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
			dtrace.SpanError(span, err)
			return fmt.Errorf(
				"failed to write packet bytes: %w", err,
			)
		}
		span.AddEvent("sent packet")

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
