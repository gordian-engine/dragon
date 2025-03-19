package cbmt

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle"
)

// Tree is a binary Merkle tree.
// If its leaves are a power of 2, then all leaves have the same depth.
// Otherwise, some leaves in excess of the next smallest power of 2
// will have one more depth than the others.
//
// Create an empty tree with [NewEmptyTree],
// and then call [*Tree.Populate] to populate it with leaf data
// and all the hashes through the root.
// Populate returns a value containing all the Merkle proofs.
type Tree struct {
	// View into the backing mem slice.
	nodes [][]byte

	nLeaves uint16
}

// NewEmptyTree returns a tree that has appropriate memory allocation
// for the given number of leaves and the given hash size (in bytes).
//
// Call [*Tree.Populate] to fill in the tree.
func NewEmptyTree(nLeaves uint16, hashSize int) *Tree {
	if nLeaves <= 0 {
		panic(fmt.Errorf(
			"BUG: nLeaves must be positive (got %d)", nLeaves,
		))
	}
	if hashSize <= 0 {
		panic(fmt.Errorf(
			"BUG: hashSize must be positive (got %d)", hashSize,
		))
	}

	// Any tree where every non-leaf node has exactly two children
	// has this many nodes.
	nNodes := 2*nLeaves - 1

	// When constructing the tree, we know the exact number of leaves
	// and the size of the hash filling each node,
	// so we back the entire tree with a single slice slice.
	// We don't need a direct reference to the backing slice within the Tree.
	mem := make([]byte, int(nNodes)*hashSize)

	nodes := make([][]byte, nNodes)
	for i := range nNodes {
		start := int(i) * hashSize
		end := start + hashSize

		nodes[i] = mem[start:end]
	}

	return &Tree{
		nodes: nodes,

		nLeaves: nLeaves,
	}
}

// PopulateConfig is the configuration used for [*Tree.Populate].
type PopulateConfig struct {
	Hasher bcmerkle.Hasher

	// Nonce should be set to an unpredictable value
	// to reduce the possibility of any collision attacks.
	// In addition to the unpredictable value,
	// the caller is free to also add domain-specific data,
	// such as the block hash in a blockchain setting.
	//
	// Consumers of the tree need the same Nonce value
	// in order to successfully verify Merkle proofs.
	// Normally, the Nonce value is included in the origination header.
	Nonce []byte

	// ProofCutoffTier controls both the depth of the returned root proof,
	// and also the depth of each leaf's proof.
	//
	// At tier 0, the root proof only contains one element, the root hash.
	// At tier 1, the root proof contains the root hash and its immediate children's hashes.
	//
	// The leaf proofs never contain the Merkle root hash.
	// At tier 1, the leaf proofs end at the Merkle root's grandchildren hashes.
	ProofCutoffTier uint8
}

// PopulateResult is the result type returned by [*Tree.Populate].
//
// The byte slices in the result reference the backing memory for the Tree,
// so retaining a reference to any of those slices
// will prevent the tree's backing memory from being garbage collected.
// Likewise, none of the slices should be modified.
type PopulateResult struct {
	// RootProof is the tiered root proof as controlled by [PopulateConfig.ProofCutoffTier].
	// If the cutoff tier was 0, the root proof will only contain the Merkle tree root hash.
	// If the cutoff tier was 1, the slice will contain the root hash,
	// then the root's left child, then the root's right child.
	// At tier 2, the slice contains the root hash, the root's left child,
	// the root's right child, the root's leftmost grandchild,
	// the root's second-leftmost grandchild, and so on until the rightmost grandchild.
	//
	// The root proof is intended to be sent in the origination header.
	RootProof [][]byte

	// The proofs slice is aligned one-to-one with the leafData slice
	// passed to *Tree.Populate.
	// The depth of the values in this slice
	// complement the RootProof slice in order to reconstitute the Tree.
	Proofs [][][]byte
}

// Populate uses the leaf data and the Hasher in the given config
// to populate the entire Merkle tree.
func (t *Tree) Populate(leafData [][]byte, cfg PopulateConfig) PopulateResult {
	if len(leafData) != int(t.nLeaves) {
		panic(fmt.Errorf(
			"BUG: initialized with %d leaves, attempted to populate with %d",
			t.nLeaves, len(leafData),
		))
	}

	// cfg.ProofCutoffTier could be something larger than the actual height,
	// so clamp it to tree height.
	treeHeight := uint8(bits.Len16(t.nLeaves))
	cutoffTier := min(treeHeight, cfg.ProofCutoffTier)

	res := PopulateResult{
		// We assign the RootProof slice closer to our determination of tree shape.

		// We will initialize these values as we populate the initial leaf data.
		Proofs: make([][][]byte, len(leafData)),
	}

	h := cfg.Hasher
	lc := bcmerkle.LeafContext{
		Nonce: cfg.Nonce,
	}

	var proofLen uint16
	if cutoffTier < treeHeight {
		proofLen = uint16(treeHeight - cutoffTier - 1) // -1 because we never include root.
	}

	if t.nLeaves&(t.nLeaves-1) == 0 {
		// Leaves are a power of two, so we don't need special treatment for overflow.

		if cutoffTier == 0 {
			res.RootProof = make([][]byte, 1)
		} else if cutoffTier >= treeHeight {
			res.RootProof = make([][]byte, (2*t.nLeaves)-1)
		} else {
			res.RootProof = make([][]byte, (1<<(cutoffTier+1))-1)
		}

		// All the leaves have the same proof length,
		// so back all the leaf proofs with a single allocation first.
		var proofMem [][]byte
		if proofLen > 0 {
			proofMem = make([][]byte, proofLen*t.nLeaves)
		}

		// Write all the leaves into the first row.
		for i, leaf := range leafData {
			h.Leaf(leaf, lc, t.nodes[i][:0])

			if cutoffTier >= treeHeight {
				// The full length is 2*nLeaves - 1.
				// We are iterating over nLeaves, therefore 2*nLeaves - 1 - nLeaves = nLeaves - 1.
				res.RootProof[int(t.nLeaves)-1+i] = t.nodes[i]
			}

			// Since we've made the hash for the current leaf,
			// right-size the proof for its sibling and initialize it.
			if proofLen > 0 {
				var siblingIdx int
				if (i & 1) == 1 {
					siblingIdx = i - 1
				} else {
					siblingIdx = i + 1
				}

				// We are slicing proofMem by siblingIdx, not i,
				// so that the layout within proofMem is sequential by leaf index.
				// It may not make an actual difference,
				// but this should be significantly easier to debug if we ever need to.
				proofs := proofMem[siblingIdx*int(proofLen) : (siblingIdx+1)*int(proofLen)]
				proofs[0] = t.nodes[i]
				res.Proofs[siblingIdx] = proofs
			}

			// Manually track the encoded leaf index, which started at zero properly.
			lc.LeafIndex[1]++
			if lc.LeafIndex[1] == 0 {
				lc.LeafIndex[0]++
			}
		}

		// Now we can complete the tree with the full leaf row in place.
		t.complete(0, uint16(len(leafData)), cfg, res)
		return res
	}

	// Otherwise, there will be some overflow.

	// The full layer's width is the greatest power of two
	// that is less than the number of leaves.
	fullLayerWidth := uint16(1 << (bits.Len16(t.nLeaves) - 1))

	// Whatever number of leaves that won't fit,
	// we have to double that number
	// so that we can use pairs of nodes.
	overflow := uint16(t.nLeaves - fullLayerWidth + t.nLeaves - fullLayerWidth) // Avoiding overflow and multiplication here.

	if cutoffTier >= treeHeight {
		// The root proof includes everything.
		res.RootProof = make([][]byte, (2*t.nLeaves)-1)
	} else {
		// The root proof only has a subset.
		res.RootProof = make([][]byte, (1<<(cutoffTier+1))-1)
	}

	// Memory layout details:
	//
	// Counts 5, 6, and 7 cover three interesting cases.
	// All of those want to fit in 4 slots,
	// so they respectively have 2, 4, and 6 leaves in the overflow area,
	// resulting in a respective 1, 2, or 3 overflow nodes at the tail end
	// of the 4-node-wide layer.
	//
	// Five node layout:
	//   [3 4] 0 1 2 34 , 01 234, ...
	//
	// Six node layout:
	//   [2 3 4 5] 0 1 23 45 , 01 2345, ...
	//
	// Seven node layout:
	//   [1 2 3 4 5 6] 0 12 34 56 , 012 3456, ...
	//
	// This complicates the sibling proofs at this layer.
	// Since we are working with the memory layout from index zero,
	// which will necessarily refer to pairs of overflow nodes,
	// we can actually just treat them pairwise as their own extra proofs.
	// "Extra" as in they are the extra depth beyond the "fullLayerWidth".
	//
	// Then when we are iterating over the "normal leaves" that fit in the normal slots,
	// an odd normal leaf always has a normal sibling to the left.
	// But, if the last normal leaf has an even index,
	// then its sibling to the right is actually the overflow node.

	nNormalLeaves := len(leafData) - int(overflow)

	// Allocate all the leaf proofs in a single backing slice.
	normalProofsSize := nNormalLeaves * int(proofLen)
	overflowProofsSize := int(overflow) * (int(proofLen) + 1)
	allProofsMem := make([][]byte, normalProofsSize+overflowProofsSize)

	// The overflow proofs are subslices of the latter part of allProofsMem.
	overflowProofsMem := allProofsMem[normalProofsSize:]

	leafStartIdx := (1 << (treeHeight - 1)) - 1
	overflowLeafStartIdx := leafStartIdx + int(fullLayerWidth)

	// Spillover leaves get written first.
	for i, leaf := range leafData[nNormalLeaves:] {
		binary.BigEndian.PutUint16(lc.LeafIndex[:], uint16(nNormalLeaves+i))
		h.Leaf(leaf, lc, t.nodes[i][:0])

		if cutoffTier >= treeHeight {
			// Leaf hashes go in the root proof.
			res.RootProof[overflowLeafStartIdx+i] = t.nodes[i]
		}

		curIdx := nNormalLeaves + i
		var siblingIdx int
		if (i & 1) == 1 {
			// Odd sibling so initialize proof for left sibling.
			siblingIdx = curIdx - 1
		} else {
			// Even sibling so initialize proof for right sibling.
			siblingIdx = curIdx + 1
		}

		// Adjust offset within overflowProofsMem slice.
		pmOffset := siblingIdx - nNormalLeaves

		proofs := overflowProofsMem[pmOffset*(int(proofLen)+1) : (pmOffset+1)*(int(proofLen)+1)]
		proofs[0] = t.nodes[i]
		res.Proofs[siblingIdx] = proofs
	}

	// The normal proofs are subslices of the first part of allProofsMem.
	proofMem := allProofsMem[:normalProofsSize]

	// Now write the base leaves.
	for i, leaf := range leafData[:nNormalLeaves] {
		binary.BigEndian.PutUint16(lc.LeafIndex[:], uint16(i))

		nodeIdx := int(overflow) + i
		h.Leaf(leaf, lc, t.nodes[nodeIdx][:0])

		if cutoffTier >= treeHeight-1 {
			// Normal leaf hashes go in the root proof.

			// We would be completing the layer that is half this size,
			// so it's n-1 instead of 2n-1,
			// for calculating where to place these leaves.
			res.RootProof[int(fullLayerWidth)-1+i] = t.nodes[nodeIdx]
		}

		// Remaining work in this loop is assigning leaf proofs.
		if proofLen == 0 {
			continue
		}

		// i is counting from zero here,
		// so there no confusing arithmetic on basic even and odd checks.
		if (i & 1) == 1 {
			// Odd leaf; we definitely have a sibling to the left.
			proofs := proofMem[(i-1)*int(proofLen) : i*int(proofLen)]
			proofs[0] = t.nodes[nodeIdx]
			res.Proofs[i-1] = proofs
		} else {
			// Even leaf; it is possible our sibling was overflow.
			if i+1 == len(leafData)-int(overflow) {
				// This is the final normal leaf and it's even.
				// That means the right sibling is an overflow leaf.
				// The overflow leaf already had another overflow sibling,
				// so we always write this normal hash into its 1-index.
				// Not only that, we know that both of those overflow nodes need this leaf.
				res.Proofs[i+2][1] = t.nodes[nodeIdx] // Larger first to reduce BCE.
				res.Proofs[i+1][1] = t.nodes[nodeIdx]

				// But also, when we handled that overflow node,
				// we did not initialize the normal proof.
				// We are going to allocate for the proof now,
				// but we don't know the hash of the first proof yet.
				// res.Proofs[i] = make([][]byte, proofLen)
				res.Proofs[i] = proofMem[i*int(proofLen) : (i+1)*int(proofLen)]
			} else {
				// Not overflow, just initialize it.
				proofs := proofMem[(i+1)*int(proofLen) : (i+2)*int(proofLen)]
				proofs[0] = t.nodes[nodeIdx]
				res.Proofs[i+1] = proofs
			}
		}
	}

	// Now write the remaining overflow nodes in the full bottom layer.
	nc := bcmerkle.NodeContext{
		Nonce: cfg.Nonce,
	}
	rootProofIdxBase := int(fullLayerWidth) - 1 + nNormalLeaves
	for i := uint16(0); i < overflow/2; i++ {
		leftIdx := uint16(len(leafData)) - overflow + i + i // Two adds might be faster than a multiply.
		rightIdx := leftIdx + 1
		binary.BigEndian.PutUint16(nc.FirstLeafIndex[:], leftIdx)
		binary.BigEndian.PutUint16(nc.LastLeafIndex[:], rightIdx)

		nodeIdx := len(leafData) + int(i)

		h.Node(t.nodes[2*i], t.nodes[(2*i)+1], nc, t.nodes[nodeIdx][:0])

		if cutoffTier >= treeHeight-1 {
			// Overflow nodes go in the root proof.
			res.RootProof[rootProofIdxBase+int(i)] = t.nodes[nodeIdx]
		}

		if proofLen == 0 {
			continue
		}

		if i == 0 && (len(leafData)&1) == 1 {
			// First overflow node on an odd leaf count.
			// That means we have to fill in the final normal leaf's first proof.
			res.Proofs[len(leafData)-int(overflow)-1][0] = t.nodes[nodeIdx]
		}

		// Whether the proof is going to the left or right node,
		// is dependent not on the i index here but on the evenness or oddness
		// of the destination within the full layer.
		mergeTargetPosition := nodeIdx - int(overflow)
		if (mergeTargetPosition & 1) == 1 {
			// Odd logical position in the full row.
			if int(leftIdx-1) > 0 { // Is there a proof to our left?
				if len(res.Proofs[leftIdx-2]) > 1 {
					// Does that proof have room for us?
					// We only need to check the -2 case because
					// this proof pair is either both or neither overflow.
					res.Proofs[leftIdx-1][1] = t.nodes[nodeIdx]
					res.Proofs[leftIdx-2][1] = t.nodes[nodeIdx]
				}
			}
		} else {
			// Even logical position in the full row.
			if int(rightIdx+2) < len(res.Proofs) {
				// We don't need conditional checks for the right node.
				// We can't be sure if the left node is overflow,
				// but if we have a right node then it is definitely overflow
				// and therefore has room for a proof at index 1.
				res.Proofs[rightIdx+2][1] = t.nodes[nodeIdx]
				res.Proofs[rightIdx+1][1] = t.nodes[nodeIdx]
			}
		}
	}

	t.complete(uint(overflow), fullLayerWidth, cfg, res)
	return res
}

// complete reads the row of nodes starting at readStartIdx and of width layerWidth,
// merging them pairwise, left to right,
// and storing the results starting at writeIdx.
//
// The res argument is passed by value, not reference,
// because its outermost slices are already sized correctly,
// and complete is indexing into them directly.
func (t *Tree) complete(readStartIdx uint, layerWidth uint16, cfg PopulateConfig, res PopulateResult) {
	writeIdx := readStartIdx + uint(layerWidth)

	if layerWidth&(layerWidth-1) != 0 || layerWidth == 0 {
		panic(fmt.Errorf(
			"BUG: cannot complete binary tree with bottom width %d (must be a power of 2)",
			layerWidth,
		))
	}

	h := cfg.Hasher
	nc := bcmerkle.NodeContext{
		Nonce: cfg.Nonce,
	}

	// Track when we reach a node that included an overflow,
	// so that we can account for leaf spans correctly.
	// Default to a max value that won't be reached.
	overflowNodeStart := t.nLeaves
	if readStartIdx > 0 {
		// Only have overflow nodes when we start reading past zero.
		overflowNodeStart = layerWidth - t.nLeaves + layerWidth // Avoid multiplication and possible overflow.
	}

	baseLeafCount := overflowNodeStart
	overflowNodeCount := layerWidth - baseLeafCount

	// How many leaves that one node is worth.
	// This is adjusted in correlation with the layer width.
	spanWidth := uint16(2)

	// Track the tier that we are writing currently.
	// This determines whether the proof goes in the root proof collection
	// or directly in the sibling leaves' proofs.
	// The root tier is 0,
	// the root's children are tier 1,
	// the root's grandchildren are tier 2, and so on.
	currentTargetTier := uint16(bits.Len16(layerWidth)) - 2

	// Track the index where leaf proofs are written.
	leafProofIdx := 1

	// We always have at least one leaf proof.
	// The 0th proof is interesting because we can use it as a reference
	// for checking if a leaf proof slice has overflow length,
	// and also if that length is zero,
	// then the cutoff tier is at least as high as the tree,
	// so we don't need any leaf proofs.
	leafProofLen := len(res.Proofs[0])

	for layerWidth > 1 {
		// We need to track how many of the base leaves and overflow nodes
		// we have "consumed" during this layer iteration.
		baseLeavesRemaining := baseLeafCount
		overflowNodesRemaining := overflowNodeCount

		// Tracking for leaf spans.
		// Required for proper node hashes.
		leafStart := uint16(0)

		// We need to figure out if the proof row we are writing
		// will go into the root proofs slice,
		// or if it goes into each leaf proof.
		rootProofWriteIdx := -1
		if currentTargetTier == 0 {
			rootProofWriteIdx = 0
		} else if currentTargetTier <= uint16(cfg.ProofCutoffTier) {
			rootProofWriteIdx = (1 << currentTargetTier) - 1
		}

		// When we are on an even index within the layer,
		// we track its leaf start and end values
		// so that we don't have to recalculate that value
		// when we are populating the earlier sibling proof.
		var prevEvenSiblingLeafStart, prevEvenSiblingLeafEnd uint16

		// Begin writing the next layer,
		// by iterating the current layer in pairs.
		for i := uint16(0); i < layerWidth; i += 2 {
			firstLeafIdx := leafStart
			lastLeafIdx := leafStart - 1

			leavesToConsume := spanWidth
			if baseLeavesRemaining > 0 {
				take := min(baseLeavesRemaining, leavesToConsume)

				baseLeavesRemaining -= take
				lastLeafIdx += take
				leavesToConsume -= take
			}
			if leavesToConsume > 0 {
				// We didn't consume all the base leaves,
				// so now we start taking from overflow nodes.
				lastLeafIdx += 2 * leavesToConsume
				overflowNodesRemaining -= leavesToConsume
			}

			binary.BigEndian.PutUint16(nc.FirstLeafIndex[:], firstLeafIdx)
			binary.BigEndian.PutUint16(nc.LastLeafIndex[:], lastLeafIdx)

			if (i & 2) == 0 {
				// This was an even node,
				// so track its leaf start and end
				// for reference when we are on the odd sibling node
				// and we need to fill in leaf proofs.
				prevEvenSiblingLeafStart = firstLeafIdx
				prevEvenSiblingLeafEnd = lastLeafIdx
			}

			leftNodeIdx := readStartIdx + uint(i)
			rightNodeIdx := leftNodeIdx + 1

			h.Node(t.nodes[leftNodeIdx], t.nodes[rightNodeIdx], nc, t.nodes[writeIdx][:0])

			// Now, is the hash we just calculated part of the root proofs,
			// or is it part of the leaf proofs?
			if rootProofWriteIdx >= 0 {
				res.RootProof[rootProofWriteIdx] = t.nodes[writeIdx]

				rootProofWriteIdx++
			} else if leafProofLen > 0 {
				// We have to fill in leaf proofs,
				// which means we have to calculate siblings.

				var siblingLeafStart, siblingLeafEnd uint16

				if (i & 2) == 2 {
					// We increment i by 2 each time in this loop,
					// so this condition means we are on an odd index
					// in the layer we are writing.
					// And therefore, our sibling is to the left.
					// We held on to the previous values during the outer part of the loop.

					siblingLeafStart = prevEvenSiblingLeafStart
					siblingLeafEnd = prevEvenSiblingLeafEnd
				} else {
					// Sibling to the right.
					// Work forward from the current leaf's state.

					siblingBaseLeavesRemaining := baseLeavesRemaining
					// Don't need to track the sibling overflow nodes remaining
					// since this is a one-shot.

					siblingLeavesToConsume := spanWidth

					siblingLeafStart = lastLeafIdx + 1
					siblingLeafEnd = lastLeafIdx

					if siblingBaseLeavesRemaining > 0 {
						take := min(siblingBaseLeavesRemaining, siblingLeavesToConsume)

						siblingBaseLeavesRemaining -= take
						siblingLeafEnd += take
						siblingLeavesToConsume -= take
					}
					if siblingLeavesToConsume > 0 {
						// Double since we are taking from the overflow leaves at this point.
						siblingLeafEnd += 2 * siblingLeavesToConsume
					}
				}

				// The leaf proof goes into the same index for all sibling leaves.
				// (Except for nodes covering overflow leaves.)
				for leafIdx := siblingLeafStart; leafIdx <= siblingLeafEnd; leafIdx++ {
					adjustedLeafProofIdx := leafProofIdx
					// There is probably a more obvious way to check this,
					// but we know that the proof for leaf zero is always the minimal value.
					// Then if the list of proofs for the target leaf has a higher length,
					// that target leaf must be an overflow node.
					if len(res.Proofs[leafIdx]) > leafProofLen {
						adjustedLeafProofIdx++
					}

					res.Proofs[leafIdx][adjustedLeafProofIdx] = t.nodes[writeIdx]
				}
			}

			writeIdx++

			leafStart = lastLeafIdx + 1
		}

		// Updates for next layer.
		readStartIdx += uint(layerWidth)
		layerWidth >>= 1

		overflowNodeStart >>= 1
		spanWidth <<= 1

		currentTargetTier--
		leafProofIdx++
	}
}

// Leaf returns the calculated hash for the leaf at the given index.
// The caller must not retain a reference to the returned slice.
func (t *Tree) Leaf(idx uint16) []byte {
	if idx < 0 || idx >= t.nLeaves {
		panic(fmt.Errorf(
			"BUG: attempted to get leaf at index %d; must be in range [0, %d)",
			idx, t.nLeaves,
		))
	}

	if (t.nLeaves & (t.nLeaves - 1)) == 0 {
		// Leaf count is power of two:
		// we only have one subtree, so we can directly index into t.nodes.
		return t.nodes[idx]
	}

	// Consider the example of having 6 leaf values:
	// A, B, C, D, E, and F.
	// Six is not a power of two, so we will fill the row of length 4,
	// the largest power of two that is less than six.
	// Of course there isn't room for everything,
	// so instead of putting 4 leaf values in the row of 4,
	// we have to swap 2 leaf values with 2 pairs of leaves.
	// Effectively this gives us something like:
	//   A B CD EF
	//   x x x  x  C D E F
	// where an x is not represented in the Tree struct anywhere.
	// The lone C D E and F leaves are "overflow".
	//
	// In this example, to retrieve A or B (leaf index 0 or 1),
	// we have to add 4 to access node 4 or 5.
	// To retrieve C, D, E, or F (leaf index 2, 3, 4, or 5),
	// we have to subtract 2 (the number of leaves before overflow).

	// The leaves are not a power of two, so find the next largest power of two
	// for the layer that we can completely fill.
	filledLayerWidth := uint16(1 << (bits.Len16(t.nLeaves) - 1))

	// This is how many nodes couldn't fit in our width.
	nodeOverflow := t.nLeaves - filledLayerWidth

	// We are going to pair leaves together to come up with the right number of nodes.
	leafOverflow := 2 * nodeOverflow

	if idx < t.nLeaves-leafOverflow {
		return t.nodes[leafOverflow+idx]
	}

	n := idx - t.nLeaves + leafOverflow
	return t.nodes[n]
}
