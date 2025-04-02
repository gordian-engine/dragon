package cbmt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle"
)

// PartialTree is a partially filled Merkle tree,
// that can be populated one leaf at a time with accompanying proofs.
//
// This type does not hold references to any leaf data.
// Use [*PartialTree.AddLeaf] to confirm the leaf data and proof,
// and store the leaf data externally.
type PartialTree struct {
	nodes [][]byte

	// We need to track which nodes are already populated.
	// Technically we could inspect if they were zero,
	// but a bitset simplifies things.
	haveNodes *bitset.BitSet

	// Which leaves are already populated;
	// this is distinct from haveNodes,
	// as we could have the hash proof of a leaf
	// without having seen the leaf content.
	haveLeaves *bitset.BitSet

	nLeaves uint16

	hasher   bcmerkle.Hasher
	hashSize int

	nonce []byte
}

// PartialTreeConfig contains all the details for [NewPartialTree].
type PartialTreeConfig struct {
	NLeaves uint16

	Hasher   bcmerkle.Hasher
	HashSize int

	Nonce []byte

	ProofCutoffTier uint8

	RootProofs [][]byte
}

func NewPartialTree(
	cfg PartialTreeConfig,
) *PartialTree {
	nLeaves := cfg.NLeaves
	hashSize := cfg.HashSize
	rootProofCutoffTier := cfg.ProofCutoffTier
	rootProofs := cfg.RootProofs

	if exp := expectedRootProofLength(nLeaves, rootProofCutoffTier); len(rootProofs) != exp {
		panic(fmt.Errorf(
			"BUG: for cutoff tier %d, root proof length should have been %d; got %d",
			rootProofCutoffTier, exp, len(rootProofs),
		))
	}

	pt := &PartialTree{
		// Just borrow the initialization behavior from NewEmptyTree.
		nodes: NewEmptyTree(nLeaves, hashSize).nodes,

		haveNodes:  bitset.MustNew(2*uint(nLeaves) - 1),
		haveLeaves: bitset.MustNew(uint(nLeaves)),

		nLeaves: nLeaves,

		hasher:   cfg.Hasher,
		hashSize: hashSize,

		nonce: cfg.Nonce,
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

		// It should be more efficient to toggle the ranges here
		// than to set each bit individually.
		// Also since we just initialized the bits,
		// we know that FlipRange will set them.
		// (There doesn't appear to be a better method for bitset.BitSet for this.)
		pt.haveNodes.FlipRange(uint(writeIdx), uint(writeIdx)+uint(sz))
		fmt.Printf("flip range 1: %d, %d\n", writeIdx, writeIdx+sz)

		rootIdxStart += sz
		sz <<= 1
		writeIdx -= sz
	}

	if writeIdx < 0 && rootIdxStart < len(rootProofs) {
		// This indirectly indicates that we had overflow leaves.
		// They are at the end of the given rootProofs,
		// but they are at the start of the nodes.
		n := copy(pt.nodes, rootProofs[rootIdxStart:])
		fmt.Printf("copied %d nodes\n", n)

		pt.haveNodes.FlipRange(0, uint(n))
		fmt.Printf("flip range 2: %d, %d\n", 0, n)
	}

	fmt.Printf("NewPartialTree:\n")
	for i := range pt.haveNodes.Len() {
		fmt.Printf("\thave node %02d? %t\n", i, pt.haveNodes.Test(i))
	}

	return pt
}

var ErrAlreadyHadProof = errors.New("already had proof for given leaf")

var ErrIncorrectLeafData = errors.New("leaf data did not match expected hash")

var ErrInsufficientProof = errors.New("insufficient proof to add leaf")

// AddLeaf confirms that the given leaf data at the given index
// matches the given proofs.
//
// If the leaf data already exists in the partial tree,
// AddLeaf returns [ErrAlreadyHadProof].
// In cases where the partial tree was configured with root proofs
// covering the entire tree,
// this means every valid leaf will result in ErrAlreadyHadProof.
//
// If we already had the proof for the leaf but the leaf data did not match,
// [ErrIncorrectLeafData] is returned.
func (t *PartialTree) AddLeaf(leafIdx uint16, leafData []byte, proofs [][]byte) error {
	fmt.Printf("\n----------------------------\nAddLeaf: entry (leafIdx=%d)\n", leafIdx)
	// First identify spillover leaves and overflow nodes.
	// As a reminder, for a tree like this:
	//
	//   01234
	//   01 234
	//   0 1 2 34
	//   x x x x x x 3 4
	//
	// Leaves 3 and 4 are "spillover" leaves because they didn't fit into
	// the power-of-four width layer.
	// The 34 node is an "overflow node".
	// The expected layout of the nodes slice goes:
	//
	//   3, 4,
	//   0, 1, 2, 34,
	//   01, 234,
	//   01234
	//
	//
	firstSpilloverLeafIdx := t.nLeaves
	var spilloverLeafCount uint16
	var nodeIdxForLeaf int
	var fullLayerWidth uint16
	if t.nLeaves&(t.nLeaves-1) == 0 {
		// The leaves are a power of two.
		nodeIdxForLeaf = int(leafIdx)
		fullLayerWidth = t.nLeaves
	} else {
		fmt.Printf("\tnLeaves (%d) is not a power of 2\n", t.nLeaves)
		// We do have an overflow leaf index.
		fullLayerWidth = uint16(1 << (bits.Len16(t.nLeaves) - 1))
		overflowNodeCount := t.nLeaves - fullLayerWidth
		spilloverLeafCount = 2 * overflowNodeCount
		firstSpilloverLeafIdx = t.nLeaves - spilloverLeafCount
		fmt.Printf(
			"\tfullLayerWidth=%d overflowNodeCount=%d spilloverLeafCount=%d firstSpilloverLeafIdx=%d\n",
			fullLayerWidth, overflowNodeCount, spilloverLeafCount, firstSpilloverLeafIdx,
		)

		if leafIdx < firstSpilloverLeafIdx {
			nodeIdxForLeaf = int(leafIdx) + int(spilloverLeafCount)
		} else {
			nNormalLeaves := int(fullLayerWidth) - int(overflowNodeCount)
			nodeIdxForLeaf = int(leafIdx) - nNormalLeaves
		}
	}

	// We are either going to need this leaf context right now
	// for a 0-length proof, or we will need it at the end of the method.
	lc := bcmerkle.LeafContext{
		Nonce: t.nonce,
	}
	binary.BigEndian.PutUint16(lc.LeafIndex[:], leafIdx)

	// Did we record already having this leaf?
	if t.haveLeaves.Test(uint(leafIdx)) {
		curHash := make([]byte, t.hashSize)
		t.hasher.Leaf(leafData, lc, curHash[:0])
		if !bytes.Equal(t.nodes[nodeIdxForLeaf], curHash) {
			return ErrIncorrectLeafData
		}

		return ErrAlreadyHadProof
	}

	if len(proofs) == 0 {
		// Empty proofs input implies that we should already have the leaf hash.
		// We know which node it should be in.
		curHash := make([]byte, t.hashSize)
		t.hasher.Leaf(leafData, lc, curHash[:0])

		if t.haveNodes.Test(uint(nodeIdxForLeaf)) {
			if !bytes.Equal(t.nodes[nodeIdxForLeaf], curHash) {
				return ErrIncorrectLeafData
			}
			if t.haveLeaves.Test(uint(leafIdx)) {
				return ErrAlreadyHadProof
			}
			// Newly added leaf: success.
			t.haveLeaves.Set(uint(leafIdx))
			return nil
		}

		// Otherwise, they didn't provide proof for this.
		// We aren't going to bother checking the sibling here:
		// if the sibling's proof already existed
		// then this leaf's proof would have had to exist too.
		return ErrInsufficientProof
	}

	// We are going to walk through the tree once
	// to collect a minimal number of siblings.
	// TODO: we should be able to allocate fewer siblings
	// by taking consideration of the root proofs.
	// But it seems better to overallocate this slice rather than growing it,
	// since we are not retaining a reference to it.
	treeHeight := uint8(bits.Len16(t.nLeaves))
	siblings := make([]sibling, 0, treeHeight)

	// Depending on the leaf and the tree structure,
	// we are going to iterate from the bottommost full layer of the tree
	// or the second bottommost.
	var layerWidth uint16
	var layerStartNodeIdx int

	// We will use the offset of the node within the current layer,
	// on the layer above our leaf.
	var curNodeOffset int

	fmt.Printf("AddLeaf: first sibling discovery\n")
	// We have at least one proof.
	if leafIdx == firstSpilloverLeafIdx-1 && (leafIdx&(leafIdx-1) == 0) {
		fmt.Printf("\tnormal sibling to overflow node case\n")
		// If we are an even leaf, our sibling is odd to the right.
		// If our odd sibling to the right is an overflow node,
		// it spans one extra leaf.

		siblings = append(siblings, sibling{
			IsLeft:    false,
			Hash:      proofs[0],
			LeafStart: leafIdx + 1,
			LeafEnd:   leafIdx + 2,
			NodeIdx:   nodeIdxForLeaf + 1,
		})
		proofs = proofs[1:]
		fmt.Printf("\tauto calculated overflow sibling: %#v\n", siblings[len(siblings)-1])

		// We do have spillover leaves.
		// Just Len16(t.nLeaves) would be the virtual width of the spillover layer,
		// one less would be the first full layer,
		// so one less than that is the next layer.
		layerWidth = uint16(1) << ((bits.Len16(t.nLeaves)) - 2)
		layerStartNodeIdx = int(spilloverLeafCount) + (1 << (bits.Len16(t.nLeaves) - 1))
		curNodeOffset = int(leafIdx >> 1)
	} else {
		fmt.Printf("\tnormal or spillover sibling case\n")
		// Spillover and normal leaves are handled nearly the same.
		sib := sibling{
			Hash: proofs[0],
		}
		proofs = proofs[1:]

		// Our even-odd check depends on spillover or normal leaf.
		isSpillover := leafIdx >= firstSpilloverLeafIdx
		fmt.Printf("\tis spillover? (%d >= %d) %t\n",
			leafIdx, firstSpilloverLeafIdx, isSpillover,
		)
		if isSpillover {
			sib.IsLeft = (nodeIdxForLeaf & 1) == 1
		} else {
			sib.IsLeft = (leafIdx & 1) == 1
		}

		// Set up leaf spans for the sibling depending on left or right
		// and normal or spillover.
		if sib.IsLeft {
			sib.NodeIdx = nodeIdxForLeaf - 1

			if isSpillover {
				sibOffset := ((nodeIdxForLeaf - 1) / 2) * 2
				sib.LeafStart = firstSpilloverLeafIdx + uint16(sibOffset)
				sib.LeafEnd = sib.LeafStart + 1 // Always has to be +1 for spillover.
			} else {
				sibLeafIdx := leafIdx - 1
				sib.LeafStart = sibLeafIdx
				sib.LeafEnd = sibLeafIdx
			}
		} else {
			sib.NodeIdx = nodeIdxForLeaf + 1

			if isSpillover {
				sibOffset := ((nodeIdxForLeaf + 1) / 2) * 2
				sib.LeafStart = firstSpilloverLeafIdx + uint16(sibOffset)
				sib.LeafEnd = min(sib.LeafStart+1, t.nLeaves-1)
			} else {
				sibLeafIdx := leafIdx + 1
				sib.LeafStart = sibLeafIdx
				sib.LeafEnd = min(sibLeafIdx, t.nLeaves-1)
			}
		}

		siblings = append(siblings, sib)
		fmt.Printf("\tappended sibling: %#v\n", sib)
		fmt.Printf("\twas it spillover? %t\n", isSpillover)

		// Now set up the layer view.
		if isSpillover {
			layerWidth = 1 << uint16(bits.Len16(t.nLeaves)-1)
			layerStartNodeIdx = int(spilloverLeafCount)

			curNodeOffset = (int(firstSpilloverLeafIdx) + (nodeIdxForLeaf >> 1))
		} else {
			// It wasn't a spillover leaf, but our calculation
			// needs to consider whether we had a perfect binary tree.
			layerWidth = uint16(1 << (bits.Len16(t.nLeaves) - 2))
			curNodeOffset = int(leafIdx >> 1)

			if t.nLeaves&(t.nLeaves-1) == 0 {
				// It was a perfect binary tree.
				layerStartNodeIdx = int(layerWidth) << 1
			} else {
				// It wasn't a perfect binary tree.
				// That means there were spillover leaves,
				// and the leaf we just hashed was a normal leaf.
				layerStartNodeIdx = int(spilloverLeafCount>>1) + int(t.nLeaves)
			}
		}
	}

	// When merging the final sibling, it should result in this hash
	// which matches an already trusted hash.
	var expectedProofHash []byte

	normalLeafCount := t.nLeaves - spilloverLeafCount

	// Now we have the first sibling,
	// and the layer width and the node index where the layer starts;
	// so we can walk the tree until we encounter a node we already trust.
	// On the first run that will be from rootProofs,
	// but on later leaves we may encounter a sibling we've seen before.
	fmt.Printf("AddLeaf: layer iteration\n")

	// How many nodes on the bottommost full layer,
	// that each node on the current layer accounts for.
	var spanWidth uint16
	if leafIdx >= normalLeafCount {
		// It was a spillover leaf so the row we are looking at is worth 1 apiece.
		spanWidth = 1
	} else {
		spanWidth = 2
	}
	for layerWidth >= 2 {
		fmt.Printf("\tlayer width: %d\n", layerWidth)
		if t.haveNodes.Test(uint(layerStartNodeIdx + curNodeOffset)) {
			// We've encountered a hash we already trust,
			// so we don't need to accumulate any more siblings.
			expectedProofHash = t.nodes[layerStartNodeIdx+curNodeOffset]
			fmt.Printf(
				"\tencountered already trusted hash at node index %d (%d+%d): %x\n",
				layerStartNodeIdx+curNodeOffset,
				layerStartNodeIdx, curNodeOffset,
				expectedProofHash,
			)
			break
		} else {
			fmt.Printf(
				"\tdid not have hash for node index %d (%d + %d)\n",
				layerStartNodeIdx+curNodeOffset,
				layerStartNodeIdx, curNodeOffset,
			)
		}

		fmt.Printf("\tlayer iter: width=%d, curNodeOffset=%d, spanWidth=%d\n", layerWidth, curNodeOffset, spanWidth)
		sib := sibling{
			Hash: proofs[0],
		}
		if (curNodeOffset & 1) == 1 {
			// Odd node, sibling is on the left.
			sib.IsLeft = true
			sib.NodeIdx = layerStartNodeIdx + curNodeOffset - 1

		} else {
			// Even node, sibling is on the right.
			sib.NodeIdx = layerStartNodeIdx + curNodeOffset + 1
		}

		sibOffset := uint16(sib.NodeIdx - layerStartNodeIdx)
		fmt.Printf("\tsib offset=%d\n", sibOffset)

		// The number of full bottom layer nodes we have to account for.
		// At least one of these is worth only one leaf,
		// but depending on the tree shape (i.e. if there was spillover),
		// some may be worth two leaves.
		nodesAlreadyConsumed := sibOffset * spanWidth

		// Track how many normal nodes we've used up.
		// If we've exceeded this, then all other nodes we cover are worth two.
		normalNodesRemaining := normalLeafCount

		fmt.Printf("\t0) normal leaves remaining=%d\n", normalNodesRemaining)
		var leafStart uint16
		if nodesAlreadyConsumed < normalLeafCount {
			// There are enough normal nodes to cover the nodes we've consumed.
			leafStart = nodesAlreadyConsumed
			normalNodesRemaining = normalLeafCount - nodesAlreadyConsumed
		} else {
			leafStart = normalLeafCount
			normalNodesRemaining = 0
			overflowNodesConsumed := nodesAlreadyConsumed - normalLeafCount
			leafStart += 2 * overflowNodesConsumed
		}

		leafEnd := leafStart - 1
		if normalNodesRemaining > 0 {
			if spanWidth <= normalNodesRemaining {
				leafEnd += spanWidth
			} else {
				// spanWidth is more than the normal leaves remaining.
				leafEnd += normalNodesRemaining
				leafEnd += 2 * (spanWidth - normalNodesRemaining) // TODO: this seems wrong.
			}
		} else {
			// There were no normal nodes remaining,
			// so all the remaining spans are worth double.
			leafEnd += 2 * spanWidth
		}
		sib.LeafStart = leafStart
		sib.LeafEnd = leafEnd
		siblings = append(siblings, sib)
		fmt.Printf("\tJust appended sibling %d: %#v\n", len(siblings)-1, sib)

		// Setup for next iteration.
		proofs = proofs[1:]
		layerStartNodeIdx += int(layerWidth)
		layerWidth >>= 1
		curNodeOffset >>= 1

		spanWidth <<= 1
	}

	if expectedProofHash == nil {
		// We didn't set the expected proof --
		// so we must have stopped at layerWidth=1,
		// so the expected proof must be the root.
		expectedProofHash = t.nodes[len(t.nodes)-1]
		fmt.Printf(
			"\tdidn't encounter expected proof hash, so falling back to root hash %x\n",
			expectedProofHash,
		)
	}

	// Now that we have all the siblings and the expected proof hash,
	// we can confirm the sibling path to the expected proof.

	// The sibling hashes are already stored on the sibling values,
	// but since we are calculating the merged hashes,
	// temporarily store them in a single backing slice.
	// t.nodes already has one large backing slice,
	// so we will copy the values from here to there
	// if everything verifies properly.
	discoveredHashes := make([]byte, t.hashSize*(len(siblings)+1))

	fmt.Printf("AddLeaf: finalization\n")

	// Store the leaf hash first.
	// Arguably we could get by without keeping the leaf hash,
	// but it's relevant to the return value.
	t.hasher.Leaf(leafData, lc, discoveredHashes[:0])

	nc := bcmerkle.NodeContext{
		Nonce: t.nonce,
	}
	binary.BigEndian.PutUint16(nc.FirstLeafIndex[:], leafIdx)
	nc.LastLeafIndex = nc.FirstLeafIndex

	for i, sib := range siblings {
		curHashStart := i * t.hashSize
		curHash := discoveredHashes[curHashStart : curHashStart+t.hashSize]

		// Zero-length slice, because the Hasher appends to the destination.
		hashDst := discoveredHashes[curHashStart+t.hashSize : curHashStart+t.hashSize]

		if sib.IsLeft {
			fmt.Printf("\t(left: sib=%x cur=%x)\n", sib.Hash, curHash)
			binary.BigEndian.PutUint16(nc.FirstLeafIndex[:], sib.LeafStart)
			t.hasher.Node(sib.Hash, curHash, nc, hashDst)
		} else {
			fmt.Printf("\t(right: cur=%x sib=%x)\n", curHash, sib.Hash)
			binary.BigEndian.PutUint16(nc.LastLeafIndex[:], sib.LeafEnd)
			t.hasher.Node(curHash, sib.Hash, nc, hashDst)
		}

		fmt.Printf("\tJust wrote hash: %x\n", hashDst[:t.hashSize])
	}

	if !bytes.Equal(
		discoveredHashes[len(discoveredHashes)-t.hashSize:],
		expectedProofHash,
	) {
		// Panic momentarily, as we are not testing failure case yet.
		panic(fmt.Errorf("hash mismatch: got %x, expected discovered hash %x",
			discoveredHashes[len(discoveredHashes)-t.hashSize:],
			expectedProofHash,
		))
	}

	// The final hash matches the expected;
	// recall that we have one more discovered hash than siblings.
	// The final hash doesn't pair with a sibling proof,
	// so all the other hashes and their sibling hashes
	// now get stored in t.nodes.
	fmt.Printf("AddLeaf: copy hashes\n")
	t.haveLeaves.Set(uint(leafIdx))

	for i, sib := range siblings {
		var discoveredNodeIdx int
		if sib.IsLeft {
			discoveredNodeIdx = sib.NodeIdx + 1
		} else {
			discoveredNodeIdx = sib.NodeIdx - 1
		}

		hashOffset := i * t.hashSize
		copy(t.nodes[discoveredNodeIdx], discoveredHashes[hashOffset:hashOffset+t.hashSize])
		t.haveNodes.Set(uint(discoveredNodeIdx))
		fmt.Printf(
			"\tset discovered node for sibling %d, to node idx %d, with hash %x\n",
			i, discoveredNodeIdx, t.nodes[discoveredNodeIdx],
		)

		// Then also set the sibling's node details.

		copy(t.nodes[sib.NodeIdx], sib.Hash)
		t.haveNodes.Set(uint(sib.NodeIdx))
		fmt.Printf(
			"\tset sibling %d, with hash %x, to node %d\n",
			i, sib.Hash, sib.NodeIdx,
		)
	}

	return nil
}

type sibling struct {
	// Whether this sibling is the left side of the pair.
	// Important for correct hashing.
	IsLeft bool

	// The start and end leaves that this sibling covers.
	LeafStart, LeafEnd uint16

	// The index into the nodes slice of the PartialTree.
	// Needed for storing the work we've done in confirming the sibling's hash.
	NodeIdx int

	// The hash of this sibling,
	// given as the proof input.
	Hash []byte
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
