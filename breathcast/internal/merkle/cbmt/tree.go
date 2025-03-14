package cbmt

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle"
)

// Tree is a right-leaning unbalanced Merkle tree.
// Create an empty tree with [NewEmptyTree],
// and then call [*Tree.Populate] to populate it with leaf data
// and all the hashes through the root.
type Tree struct {
	// When constructing the tree, we know the exact number of leaves
	// and the size of the hash filling each node,
	// so we back the entire tree with a single memory slice.
	mem []byte

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

	mem := make([]byte, int(nNodes)*hashSize)

	nodes := make([][]byte, nNodes)
	for i := range nNodes {
		start := int(i) * hashSize
		end := start + hashSize

		nodes[i] = mem[start:end]
	}

	return &Tree{
		mem:   mem,
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
	ProofCutoffTier uint16
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

	res := PopulateResult{
		RootProof: make([][]byte, (1<<(cfg.ProofCutoffTier+1))-1),
		Proofs:    make([][][]byte, len(leafData)),
	}

	h := cfg.Hasher
	lc := bcmerkle.LeafContext{
		Nonce: cfg.Nonce,
	}

	if t.nLeaves&(t.nLeaves-1) == 0 {
		treeHeight := uint16(bits.Len16(t.nLeaves))
		var proofLen uint16
		if cfg.ProofCutoffTier < treeHeight {
			proofLen = treeHeight - cfg.ProofCutoffTier - 1 // -1 because we never include root.
		}

		// Leaves are a power of two, so we don't need special treatment.
		// Write all the leaves into the first row.
		for i, leaf := range leafData {
			h.Leaf(leaf, lc, t.nodes[i][:0])

			// Since we've made the hash for the current leaf,
			// right-size the proof for its sibling and initialize it.
			if proofLen > 0 {
				var siblingIdx int
				if (i & 1) == 1 {
					siblingIdx = i - 1
				} else {
					siblingIdx = i + 1
				}
				res.Proofs[siblingIdx] = make([][]byte, proofLen)
				res.Proofs[siblingIdx][0] = t.nodes[i]
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

	// Memory layout details:
	//
	// Counts 5, 6, and 7 cover three interesting cases.
	// All of those want ot fit in 4 slots,
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

	treeHeightBeforeOverflow := uint16(bits.Len16(t.nLeaves))
	var proofLen uint16
	if cfg.ProofCutoffTier < treeHeightBeforeOverflow {
		proofLen = treeHeightBeforeOverflow - cfg.ProofCutoffTier - 1 // -1 because we never include root.
	}

	// Overflow leaves get written first.
	for i, leaf := range leafData[len(leafData)-int(overflow):] {
		binary.BigEndian.PutUint16(lc.LeafIndex[:], uint16(len(leafData)-int(overflow)+i))
		h.Leaf(leaf, lc, t.nodes[i][:0])

		// Initialize the proofs for the sibling.
		proofs := make([][]byte, proofLen+1)
		proofs[0] = t.nodes[i]
		curIdx := len(leafData) - int(overflow) + i
		if (i & 1) == 1 {
			// Odd sibling so initialize proof for left sibling.
			res.Proofs[curIdx-1] = proofs
		} else {
			// Even sibling so initialize proof for right sibling.
			res.Proofs[curIdx+1] = proofs
		}
	}

	// Then write the earlier leaves.
	for i, leaf := range leafData[:len(leafData)-int(overflow)] {
		binary.BigEndian.PutUint16(lc.LeafIndex[:], uint16(i))

		nodeIdx := int(overflow) + i
		h.Leaf(leaf, lc, t.nodes[nodeIdx][:0])

		// i is counting from zero here,
		// so there no confusing arithmetic on basic even and odd checks.
		if (i & 1) == 1 {
			// Odd leaf; we definitely have a sibling to the left.
			proofs := make([][]byte, proofLen)
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
				res.Proofs[i] = make([][]byte, proofLen)
			} else {
				// Not overflow, just initialize it.
				proofs := make([][]byte, proofLen)
				proofs[0] = t.nodes[nodeIdx]
				res.Proofs[i+1] = proofs
			}
		}
	}

	nc := bcmerkle.NodeContext{
		Nonce: cfg.Nonce,
	}
	for i := uint16(0); i < overflow/2; i++ {
		leftIdx := uint16(len(leafData)) - overflow + i + i // Two adds might be faster than a multiply.
		rightIdx := leftIdx + 1
		binary.BigEndian.PutUint16(nc.FirstLeafIndex[:], leftIdx)
		binary.BigEndian.PutUint16(nc.LastLeafIndex[:], rightIdx)
		h.Node(t.nodes[2*i], t.nodes[(2*i)+1], nc, t.nodes[len(leafData)+int(i)][:0])

		if i == 0 && (len(leafData)&1) == 1 {
			// First overflow node on an odd leaf count.
			// That means we have to fill in the final normal leaf's first proof.
			res.Proofs[len(leafData)-int(overflow)-1][0] = t.nodes[len(leafData)+int(i)]
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
		fullLayerWidth := uint16(1 << (bits.Len16(t.nLeaves) - 1))
		overflowNodeStart = t.nLeaves - fullLayerWidth
	}

	// How many leaves that one node is worth.
	spanWidth := uint16(2)

	// Track the tier that we are writing currently.
	// The root tier is 0,
	// the root's children are tier 1,
	// the root's grandchildren are tier 2, and so on.
	currentTargetTier := uint16(bits.Len16(layerWidth)) - 2

	// Track the index where leaf proofs are written.
	leafProofIdx := 1

	for layerWidth > 1 {
		// Tracking for leaf spans.
		// Required for proper node hashes.
		spanStart := uint16(0)

		// We need to figure out if the proof row we are writing
		// will go into the root proofs slice,
		// or if it goes into each leaf proof.
		rootProofWriteIdx := -1
		if currentTargetTier == 0 {
			rootProofWriteIdx = 0
		} else if currentTargetTier <= cfg.ProofCutoffTier {
			rootProofWriteIdx = 2*int(currentTargetTier) - 1
		}
		for i := uint16(0); i < layerWidth; i += 2 {
			// Set up the leaf indices for the hash.
			firstLeafIdx := spanStart
			lastLeafIdx := firstLeafIdx - 1 + spanWidth
			if layerWidth == 2 {
				// Don't try to calculate the end.
				// We are merging the root, so it must span all leaves.
				lastLeafIdx = t.nLeaves - 1
			} else if i >= overflowNodeStart {
				// The nodes we are merging, are worth one more span.
				lastLeafIdx += spanWidth
			}

			binary.BigEndian.PutUint16(nc.FirstLeafIndex[:], firstLeafIdx)
			binary.BigEndian.PutUint16(nc.LastLeafIndex[:], lastLeafIdx)

			leftNodeIdx := readStartIdx + uint(i)
			rightNodeIdx := leftNodeIdx + 1

			h.Node(t.nodes[leftNodeIdx], t.nodes[rightNodeIdx], nc, t.nodes[writeIdx][:0])

			// Now, is the hash we just calculated part of the root proofs,
			// or is it part of the leaf proofs?
			if rootProofWriteIdx >= 0 {
				res.RootProof[rootProofWriteIdx] = t.nodes[writeIdx]

				rootProofWriteIdx++
			} else {
				// Calculate sibling range based on current span.
				pairSize := spanWidth * 2
				pairStart := (firstLeafIdx / pairSize) * pairSize

				var siblingStart, siblingEnd uint16

				if firstLeafIdx == pairStart {
					// Left side of the pair, so sibling is on the right.
					siblingStart = firstLeafIdx + spanWidth
					siblingEnd = siblingStart + spanWidth - 1
					if siblingEnd >= overflowNodeStart {
						// Expand the end by one more span,
						// so that we copy in the proofs correctly.
						siblingEnd += spanWidth
					}
					siblingEnd = min(siblingEnd, t.nLeaves-1)
				} else {
					// Right side of the pair, so sibling is on the left.
					siblingStart = pairStart
					siblingEnd = siblingStart + spanWidth - 1
				}

				// The leaf proof goes into the same index for all sibling leaves.
				// (Except for nodes covering overflow leaves.)
				for leafIdx := siblingStart; leafIdx <= siblingEnd; leafIdx++ {
					adjustedLeafProofIdx := leafProofIdx
					// There is probably a more obvious way to check this,
					// but we know that the proof for leaf zero is always the minimal value.
					// Then if the list of proofs for the target leaf has a higher length,
					// that target leaf must be an overflow node.
					// TODO: improve this check.
					if len(res.Proofs[leafIdx]) > len(res.Proofs[0]) {
						adjustedLeafProofIdx++
					}

					res.Proofs[leafIdx][adjustedLeafProofIdx] = t.nodes[writeIdx]
				}
			}

			writeIdx++

			spanStart = lastLeafIdx + 1
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

// Root returns the calculated hash for the tree root.
// The caller must not retain a reference to the returned slice.
func (t *Tree) Root() []byte {
	return t.nodes[len(t.nodes)-1]
}

func (t *Tree) GenerateProof(leafIdx uint16, dst [][]byte) [][]byte {
	if leafIdx < 0 || leafIdx >= t.nLeaves {
		panic(fmt.Errorf(
			"leafIndex must be in range [0, %d); got %d",
			t.nLeaves, leafIdx,
		))
	}

	nodes := t.nodes
	bottomLayerWidth := t.nLeaves
	if (t.nLeaves & (t.nLeaves - 1)) != 0 {
		// Not a power of 2, so we have to make some adjustments.

		// For logical tree like:
		//   0 1 23 45
		//   x x x x 2 3 4 5
		//
		// This is laid out in memory like:
		//   2 3 4 5 0 1 23 45
		//   ^ ^ ^ ^     ^^ ^^
		//   | | | |     ++-++--- "node overflow"
		//   | | | |
		//   | | | |
		//   +-+-+-+--- "leaf overflow"
		//
		// The bottomLayerWidth is 4.
		// nLeaves is 6.
		// nodeOverflow is 2 (have 6 leaves, want to fit into width of 4).
		// leafOverflow is 4 (double nodeOverflow for number of leaves in overflow area).

		bottomLayerWidth = uint16(1 << (bits.Len16(t.nLeaves) - 1))

		// This is how many nodes couldn't fit in our width.
		nodeOverflow := t.nLeaves - bottomLayerWidth

		// We are going to pair leaves together to come up with the right number of nodes.
		leafOverflow := 2 * nodeOverflow

		nodes = t.nodes[leafOverflow:]

		if leafIdx >= t.nLeaves-leafOverflow {
			// The leaf requested is an overflow leaf.
			// Include the overflow proof first,
			// then normalize leafIdx to the full bottom row of the tree.

			oIdx := leafIdx - t.nLeaves + leafOverflow
			if (oIdx & 1) == 1 {
				// Odd index, use left sibling.
				dst = append(dst, t.nodes[oIdx-1])
			} else {
				// Even index, use right sibling.
				dst = append(dst, t.nodes[oIdx+1])
			}

			// Now adjust leafIdx so it's relative to the actual row,
			// not the overflow row.
			leafIdx = t.nLeaves - leafOverflow + ((oIdx) / 2)
		}
	}

	for bottomLayerWidth >= 2 {
		if (leafIdx & 1) == 1 {
			// Odd node, use left sibling.
			dst = append(dst, nodes[leafIdx-1])
		} else {
			// Even node, use right sibling.
			dst = append(dst, nodes[leafIdx+1])
		}

		nodes = nodes[bottomLayerWidth:]
		leafIdx >>= 1
		bottomLayerWidth >>= 1
	}

	return dst
}
