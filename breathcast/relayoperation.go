package breathcast

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/klauspost/reedsolomon"
	"github.com/quic-go/quic-go"
)

// RelayOperation is the operation for accepting an incoming broadcast.
//
// Instances must be created through [*Protocol.CreateRelayOperation].
//
// The application owns management of any live relay operations,
// and the application is responsible for routing incoming streams
// to the [*RelayOperation.AcceptBroadcast] method.
type RelayOperation struct {
	log *slog.Logger

	// The protocol that owns the operation,
	// so we can enter through its main loop.
	p *Protocol

	enc reedsolomon.Encoder

	acceptBroadcastRequests chan acceptBroadcastRequest

	ackTimeout time.Duration

	workerWG sync.WaitGroup
}

type acceptBroadcastRequest struct {
	S    quic.Stream
	Resp chan struct{}
}

func (o *RelayOperation) run(ctx context.Context, shards [][]byte) {
	// Assume that when we begin a relay operation, we have populated shards.
	// Note that we can't rely on the length of the shards,
	// as reedsolomon.AllocAligned sets the slices to non-zero length.
	have := bitset.New(uint(len(shards)))
	_ = have

	for {
		select {
		case <-ctx.Done():
			o.log.Info(
				"Stopping due to context cancellation",
				"cause", context.Cause(ctx),
			)
			return

		case req := <-o.acceptBroadcastRequests:
			// TODO: we should invoke the worker differently depending on
			// how many shards we already have.
			//
			// No shards is a trivial case.
			o.workerWG.Add(1)
			w := &relayWorker{
				log: o.log.With("broadcast_stream", req.S.StreamID()),

				op: o,
			}
			go w.AcceptBroadcastFromEmpty(ctx, req.S)
			close(req.Resp)
		}
	}
}

// AcceptBroadcast accepts the incoming broadcast handshake,
// replying with a protocol-specific message indicating what shards
// the operation instance already has.
func (o *RelayOperation) AcceptBroadcast(ctx context.Context, s quic.Stream) error {
	req := acceptBroadcastRequest{
		S:    s,
		Resp: make(chan struct{}),
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while making request to accept broadcast: %w",
			context.Cause(ctx),
		)
	case o.acceptBroadcastRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while waiting for response to accept broadcast: %w",
			context.Cause(ctx),
		)
	case <-req.Resp:
		return nil
	}
}

type RelayOperationConfig struct {
	// The header for this specific relay operation.
	OperationHeader []byte

	// The Merkle root proof
	// and possibly some of its descendants.
	RootProof [][]byte

	// The number of data and parity chunks;
	// required for proper Merkle tree reconstitution.
	NData, NParity uint16

	// Shard size is the size of the underlying erasure-coded shards.
	// Necessary for reconstituting the original application data.
	ShardSize uint16

	AckTimeout time.Duration
}
