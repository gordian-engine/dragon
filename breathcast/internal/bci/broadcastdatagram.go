package bci

import (
	"encoding/binary"
	"math/bits"
)

// BroadcastDatagram is the structured content
// contained in the datagrams sent as part of broadcast.
type BroadcastDatagram struct {
	// The protocol ID is omitted.

	BroadcastID []byte
	ChunkIndex  uint16

	Proofs [][]byte
	Data   []byte
}

// ParseBroadcastDatagram extracts the BroadcastDatagram from b.
//
// Byte slice fields of the returned BroadcastDatagram
// retain references into b, so they must not be modified.
func ParseBroadcastDatagram(
	datagram []byte,
	bidSz uint8,
	nChunks uint16,
	rootProofsLen uint,
	hashSz int,
) BroadcastDatagram {
	chunkIdx := binary.BigEndian.Uint16(datagram[1+bidSz : 1+bidSz+2])
	d := BroadcastDatagram{
		// Not keeping the protocol ID.
		BroadcastID: datagram[1 : 1+bidSz],
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
		proofs[i] = datagram[idxOffset : idxOffset+hashSz]
		idxOffset += hashSz
	}
	d.Proofs = proofs

	// Assume the entire remainder of the slice
	// is the raw data.
	d.Data = datagram[idxOffset:]

	return d
}
