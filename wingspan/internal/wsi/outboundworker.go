package wsi

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// OutboundWorker manages the outbound stream
// to a particular peer, for a particular session.
type OutboundWorker struct {
	log *slog.Logger

	header []byte
}

// NewOutboundWorker returns a new OutboundWorker.
func NewOutboundWorker(
	log *slog.Logger,
	header []byte,
) *OutboundWorker {
	return &OutboundWorker{
		log: log,

		header: header,
	}
}

// Run executes the main loop of outbound work.
// It is intended to be run in its own goroutine.
func (w *OutboundWorker) Run(
	ctx context.Context,
	parentWG *sync.WaitGroup,
	conn quic.Connection,
	headerTimeout time.Duration,
) {
	defer parentWG.Done()

	s, err := w.initializeStream(ctx, conn, headerTimeout)
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

	for {
		select {
		case <-ctx.Done():
			return

			// TODO: handle new data and forward it on the stream.
		}
	}
}

func (w *OutboundWorker) initializeStream(
	ctx context.Context,
	conn quic.Connection,
	headerTimeout time.Duration,
) (quic.SendStream, error) {
	s, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.SetWriteDeadline(time.Now().Add(headerTimeout)); err != nil {
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
