package breathcast

import (
	"context"
	"fmt"
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
	// The protocol that owns the operation,
	// so we can enter through its main loop.
	p *Protocol

	enc reedsolomon.Encoder

	ackTimeout time.Duration

	mu     sync.RWMutex
	shards [][]byte
	have   *bitset.BitSet
}

// AcceptBroadcast accepts the incoming broadcast handshake,
// replying with a protocol-specific message indicating what shards
// the operation instance already has.
func (o *RelayOperation) AcceptBroadcast(ctx context.Context, s quic.Stream) error {
	o.mu.RLock()
	haveCount := o.have.Count()
	o.mu.RUnlock()

	if err := s.SetWriteDeadline(time.Now().Add(o.ackTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline before sending ack: %w", err)
	}

	if haveCount == 0 {
		// Special case: we only send the zero byte,
		// and the originator understands we have nothing yet.
		if _, err := s.Write([]byte{0}); err != nil {
			return fmt.Errorf("failed to write have-nothing acknowledgement: %w", err)
		}

		return nil
	}

	panic(fmt.Errorf("TODO: handle case for haveCount=%d", haveCount))
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
