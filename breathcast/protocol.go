package breathcast

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/dconn"
)

// Protocol controls all the operations of the "breathcast" broadcasting protocol.
type Protocol struct {
	log *slog.Logger

	connChanges       <-chan dconn.Change
	originateRequests chan originateRequest

	// Application-decided protocol ID to use for Breathcast.
	// Maybe we don't need this since the application
	// is supposed to route requests here?
	protocolID byte

	// Tracks the mainLoop goroutine and the connection worker goroutines.
	wg sync.WaitGroup
}

// ProtocolConfig is the configuration passed to [NewProtocol].
type ProtocolConfig struct {
	// The initial connections to use.
	// The protocol will own this slice,
	// so the caller must not retain any references to it.
	InitialConnections []dconn.Conn

	// How to inform the protocol of connection changes.
	ConnectionChanges <-chan dconn.Change

	// The single header byte to be sent on outgoing streams.
	ProtocolID byte
}

// NewProtocol returns a new Protocol value with the given configuration.
// The given context controls the lifecycle of the Protocol.
func NewProtocol(ctx context.Context, log *slog.Logger, cfg ProtocolConfig) *Protocol {
	p := &Protocol{
		log: log,

		connChanges: cfg.ConnectionChanges,

		// Unbuffered since the caller blocks on it.
		originateRequests: make(chan originateRequest),

		protocolID: cfg.ProtocolID,
	}

	connWorkers := make(map[string]*connectionWorker, len(cfg.InitialConnections))
	for _, conn := range cfg.InitialConnections {
		wCtx, cancel := context.WithCancel(ctx)

		w := &connectionWorker{
			Ctx:    wCtx,
			Cancel: cancel,

			Log: p.log.With("conn", conn.QUIC.RemoteAddr().String()),

			QUIC:  conn.QUIC,
			Chain: conn.Chain,

			Originations: make(chan origination, 4), // Arbitrarily sized at 4.
		}

		p.wg.Add(1)
		go w.Work(&p.wg)
		connWorkers[string(conn.Chain.Leaf.RawSubjectPublicKeyInfo)] = w
	}

	p.wg.Add(1)
	go p.mainLoop(ctx, connWorkers)

	return p
}

// Wait blocks until all of p's background work has finished.
// The background work will begin stopping once the context
// passed to [NewProtocol] is canceled.
func (p *Protocol) Wait() {
	p.wg.Wait()
}

func (p *Protocol) mainLoop(ctx context.Context, connWorkers map[string]*connectionWorker) {
	defer p.wg.Done()

	for {
		select {
		case <-ctx.Done():
			p.log.Info(
				"Stopping due to context cancellation",
				"cause", context.Cause(ctx),
			)

			// We don't need to cancel any of the workers,
			// because all of their contexts were derived from this ctx.
			return

		case change := <-p.connChanges:
			key := string(change.Conn.Chain.Leaf.RawSubjectPublicKeyInfo)
			w, have := connWorkers[key]

			if change.Adding {
				if have {
					panic(fmt.Errorf(
						"BUG: attempted to add identical leaf certificate %q twice", key,
					))
				}

				wCtx, cancel := context.WithCancel(ctx)
				w := &connectionWorker{
					Ctx:    wCtx,
					Cancel: cancel,

					Log: p.log.With("conn", change.Conn.QUIC.RemoteAddr().String()),

					QUIC:  change.Conn.QUIC,
					Chain: change.Conn.Chain,

					Originations: make(chan origination, 4), // Arbitrarily sized at 4.
				}

				p.wg.Add(1)
				go w.Work(&p.wg)
				connWorkers[key] = w
			} else {
				if !have {
					panic(fmt.Errorf(
						"BUG: attempted to remove leaf certificate %q that did not exist", key,
					))
				}

				w.Cancel()
				delete(connWorkers, key)
			}

		case req := <-p.originateRequests:
			// Fan out this request to every connection worker.
			// This blocks the main loop,
			// which seems necessary since we retain the only copy
			// of the connection worker map.
			for _, cw := range connWorkers {
				select {
				case cw.Originations <- req.O:
					// Okay.
				default:
					// We could possibly just drop the connection here.
					// Or we could collect the blocked ones in a slice and retry one more time.
					// Not very clear what the best solution is, yet.
					panic(fmt.Errorf(
						"TODO: decide how to handle blocked send on origination work",
					))
				}
			}

			close(req.Resp)
		}
	}
}

// OriginateTask is the result of calling [*Protocol.Originate].
type OriginateTask struct {
	// TODO: what details should this expose?
}

// Originate begins a broadcast to all peers in the active view.
// headerData is an application-specific encoding.
//
// The header data must contain details for the partial Merkle tree,
// the number of data and parity chunks,
// the chunk size, and the full reconstructed data size.
// It may contain any other application-specific data.
//
// The header is sent over a reliable QUIC stream,
// before the fragments are sent over unreliable datagrams,
// so the header data should be concise within reason.
//
// The returned task will remain active until the context is finished.
// That is, the protocol will send the origination to any new connections
// while the task is still active.
//
// The caller should use [context.WithCancelCause] with a TBD error
// in order to signal a proper finish of an originate task,
// distinct from other interrupt-style context cancellations.
func (p *Protocol) Originate(
	ctx context.Context,
	headerData []byte,
	dataChunks [][]byte,
	parityChunks [][]byte,
) (OriginateTask, error) {
	t := OriginateTask{}

	resp := make(chan struct{})
	req := originateRequest{
		O: origination{
			Ctx: ctx,

			// TODO: these should be configurable.
			OpenStreamTimeout: 50 * time.Millisecond,
			SendHeaderTimeout: 50 * time.Millisecond,

			ProtocolID: p.protocolID,

			Header:       headerData,
			DataChunks:   dataChunks,
			ParityChunks: parityChunks,
		},
		Resp: resp,
	}

	select {
	case <-ctx.Done():
		return t, fmt.Errorf(
			"context canceled while sending origination request: %w",
			context.Cause(ctx),
		)
	case p.originateRequests <- req:
		return t, nil
	}
}

type origination struct {
	Ctx context.Context

	OpenStreamTimeout time.Duration
	SendHeaderTimeout time.Duration

	ProtocolID byte

	Header       []byte
	DataChunks   [][]byte
	ParityChunks [][]byte
}

type originateRequest struct {
	O origination

	Resp chan struct{}
}
