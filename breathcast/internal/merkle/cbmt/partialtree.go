package cbmt

import (
	"fmt"
	"math/bits"
)

// PartialTree is a partially filled Merkle tree,
// that can be populated one leaf at a time with accompanying proofs.
type PartialTree struct {
	nodes [][]byte

	nLeaves uint16
}

func NewPartialTree(
	nLeaves uint16,
	hashSize int,
	rootProofCutoffTier uint8,
	rootProofs [][]byte,
) *PartialTree {
	if exp := expectedRootProofLength(nLeaves, rootProofCutoffTier); len(rootProofs) != exp {
		panic(fmt.Errorf(
			"BUG: for cutoff tier %d, root proof length should have been %d; got %d",
			rootProofCutoffTier, exp, len(rootProofs),
		))
	}

	pt := &PartialTree{
		// Just borrow the initialization behavior from NewEmptyTree.
		nodes:   NewEmptyTree(nLeaves, hashSize).nodes,
		nLeaves: nLeaves,
	}

	// Now we are going to copy the root proofs into their respective slots in the nodes.
	// The rootProofs value is in reverse order from the nodes layout,
	// so we have to iterate backwards through one of them.
	// Currently we read forwards through the rootProofs
	// and write from the end of nodes,
	// jumping backwards in the nodes and then writing forwards a chunk.
	rootIdxStart := 0
	sz := 1
	writeIdx := len(pt.nodes) - 1

	for rootIdxStart < len(rootProofs) && writeIdx >= 0 {
		for ri := range sz {
			if len(rootProofs[rootIdxStart+ri]) != hashSize {
				panic(fmt.Errorf(
					"BUG: every root proof must be %d bytes, but index %d had length %d",
					hashSize, rootIdxStart+ri, len(rootProofs[rootIdxStart+ri]),
				))
			}

			copy(pt.nodes[writeIdx+ri], rootProofs[rootIdxStart+ri])
		}

		rootIdxStart += sz
		sz <<= 1
		writeIdx -= sz
	}

	if writeIdx < 0 && rootIdxStart < len(rootProofs) {
		// This indirectly indicates that we had overflow leaves.
		// They are at the end of the given rootProofs,
		// but they are at the start of the
		copy(pt.nodes, rootProofs[rootIdxStart:])
	}

	return pt
}

func expectedRootProofLength(nLeaves uint16, cutoffTier uint8) int {
	// TODO: this is simpler than the existing logic in *Tree.Populate,
	// so we should port this over there.

	if cutoffTier == 0 {
		return 1
	}

	// Is it the whole tree?
	treeHeight := uint16(bits.Len16(nLeaves))
	if uint16(cutoffTier) >= treeHeight {
		return (2 * int(nLeaves)) - 1
	}

	// It's only a subset of the tree.
	return (1 << (cutoffTier + 1)) - 1
}
