package breathcast

import (
	"context"
	"log/slog"
	"sync"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/quic-go/quic-go"
)

// connectionWorker manages the protocol work belonging to a single connection.
type connectionWorker struct {
	Ctx    context.Context
	Cancel context.CancelFunc

	Log *slog.Logger

	QUIC  quic.Connection
	Chain dcert.Chain

	Originations chan origination

	// TODO: identify how the relay operation occurs.
	// Missing a lot of glue for that yet.
	Relays chan struct{}

	wg sync.WaitGroup
}

func (w *connectionWorker) Work(parentWG *sync.WaitGroup) {
	defer parentWG.Done()

	for {
		select {
		case <-w.Ctx.Done():
			w.Log.Info("Stopping due to context cancellation", "cause", context.Cause(w.Ctx))

			// Wait for all the origination workers to finish,
			// before the deferred parentWG.Done call runs.
			//
			// It is possible that we may need to proactively cancel
			// the worker goroutines somehow;
			// otherwise we risk deadlocking here.
			w.wg.Wait()

			return

		case o := <-w.Originations:
			w.wg.Add(1)
			ow := &originationWorker{
				// TODO: the log should have another detail about the exact origination here.
				log: w.Log.With("worker", "origination"),

				cw: w,
			}

			go ow.run(o)

		case _ = <-w.Relays:
			// TODO: handle relay operations.
		}
	}
}
