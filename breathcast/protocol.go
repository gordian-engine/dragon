package breathcast

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gordian-engine/dragon/dconn"
)

// Protocol controls all the operations of the "breathcast" broadcasting protocol.
type Protocol struct {
	log *slog.Logger

	connChanges <-chan dconn.Change

	// Application-decided protocol ID to use for Breathcast.
	// Maybe we don't need this since the application
	// is supposed to route requests here?
	protocolID byte

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
}

// NewProtocol returns a new Protocol value with the given configuration.
// The given context controls the lifecycle of the Protocol.
func NewProtocol(ctx context.Context, log *slog.Logger, cfg ProtocolConfig) *Protocol {
	p := &Protocol{
		log: log,

		connChanges: cfg.ConnectionChanges,
	}

	p.wg.Add(1)
	go p.mainLoop(ctx, cfg.InitialConnections)

	return p
}

// Wait blocks until all of p's background work has finished.
// The background work will begin stopping once the context
// passed to [NewProtocol] is canceled.
func (p *Protocol) Wait() {
	p.wg.Wait()
}

func (p *Protocol) mainLoop(ctx context.Context, conns []dconn.Conn) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			p.log.Info(
				"Stopping due to context cancellation",
				"cause", context.Cause(ctx),
			)
			return

		case change := <-p.connChanges:
			if change.Adding {
				conns = append(conns, change.Conn)
			} else {
				removed := false
				for i, c := range conns {
					if !change.Conn.Chain.Leaf.Equal(c.Chain.Leaf) {
						continue
					}

					// Found our leaf.
					// Swap the last position of connections with current.
					conns[i] = conns[len(conns)-1]
					conns[len(conns)-1] = dconn.Conn{} // Zero out entry for GC.
					conns = conns[:len(conns)-1]

					removed = true
					break
				}

				if !removed {
					panic(fmt.Errorf(
						"BUG: attempted to remove connection %#v but it was not in list",
						change.Conn,
					))
				}
			}

			// TODO: this needs to also output to every in-progress operation.
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
) OriginateTask {
	return OriginateTask{}
}
