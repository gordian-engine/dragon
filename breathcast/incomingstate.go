package breathcast

import (
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/gordian-engine/dragon/dpubsub"
	"github.com/klauspost/reedsolomon"
)

// incomingState is the shared state of incoming data during a broadcast.
type incomingState struct {
	// The Merkle tree that we are reconstituting from peers.
	pt *cbmt.PartialTree

	// We are currently using clones for splitting PartialTree work
	// to other goroutines.
	//
	// When the other goroutines finish with their clone,
	// the clone is appended to this list
	// so it can be reclaimed the next time we need a clone.
	treeClones []*cbmt.PartialTree

	nData, nParity uint16

	enc    reedsolomon.Encoder
	shards [][]byte

	rootProof [][]byte

	// Consumers of incomingState are initialized with a copy of
	// the pt.HaveLeaves bit set.
	// They can observe this pubsub stream for updates to which leaves
	// have been successfully added.
	//
	// The BroadcastOperation is responsible for setting this field,
	// so consumers must be very careful to make a copy of the field
	// and track that copy, rather than accessing the field directly
	// from the incomingState struct.
	addedLeafIndices *dpubsub.Stream[uint]
}
