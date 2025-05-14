package bci

import (
	"encoding/binary"
	"math/bits"
)

// BroadcastPacket is the structured content
// contained in the packets sent as part of broadcast.
type BroadcastPacket struct {
	// The protocol ID is omitted.

	BroadcastID []byte
	ChunkIndex  uint16

	Proofs [][]byte
	Data   []byte
}

// ParseBroadcastPacket extracts the BroadcastPacket from b.
//
// Byte slice fields of the returned BroadcastPacket
// retain references into b, so they must not be modified.
func ParseBroadcastPacket(
	b []byte,
	bidSz uint8,
	nChunks uint16,
	rootProofsLen uint,
	hashSz int,
) BroadcastPacket {
	chunkIdx := binary.BigEndian.Uint16(b[1+bidSz : 1+bidSz+2])
	bp := BroadcastPacket{
		// Not keeping the protocol ID.
		BroadcastID: b[1 : 1+bidSz],
		ChunkIndex:  chunkIdx,
	}

	// Now, the number of proofs depends on whether this was a spillover leaf.
	// This requires a bit of knowledge about the structure of the cbmt Merkle tree.

	treeHeight := bits.Len16(nChunks)
	proofLen := treeHeight - bits.Len(rootProofsLen)
	hasSpillover := nChunks&(nChunks-1) != 0
	if hasSpillover {
		// The leaves weren't a power of two.
		// Increment the tree height for spillover.
		treeHeight++
		// And if we are indexing a leaf that would be spillover,
		// increment the proof length for it too.
		spilloverCount := nChunks - uint16(1<<(treeHeight-2))
		if chunkIdx >= nChunks-(spilloverCount*2) {
			proofLen++
		}
	}
	proofs := make([][]byte, proofLen)

	idxOffset := 1 + int(bidSz) + 2
	for i := range proofs {
		proofs[i] = b[idxOffset : idxOffset+hashSz]
		idxOffset += hashSz
	}
	bp.Proofs = proofs

	// Assume the entire remainder of the slice
	// is the raw data.
	bp.Data = b[idxOffset:]

	return bp
}
