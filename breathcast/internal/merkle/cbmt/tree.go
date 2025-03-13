package cbmt

import (
	"encoding/binary"
	"fmt"
	"math/bits"
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
	Hasher Hasher

	Nonce []byte
}

// Populate uses the leaf data and the Hasher in the given config
// to populate the entire Merkle tree.
func (t *Tree) Populate(leafData [][]byte, cfg PopulateConfig) {
	if len(leafData) != int(t.nLeaves) {
		panic(fmt.Errorf(
			"BUG: initialized with %d leaves, attempted to populate with %d",
			t.nLeaves, len(leafData),
		))
	}

	h := cfg.Hasher
	lc := LeafContext{
		Nonce: cfg.Nonce,
	}

	if t.nLeaves&(t.nLeaves-1) == 0 {
		// Leaves are a power of two, so we don't need special treatment.
		// Write all the leaves into the first row.
		for i, leaf := range leafData {
			h.Leaf(leaf, lc, t.nodes[i][:0])

			// Manually track the encoded leaf index, which started at zero properly.
			lc.LeafIndex[1]++
			if lc.LeafIndex[1] == 0 {
				lc.LeafIndex[0]++
			}
		}

		// Now we can complete the tree with the full leaf row in place.
		t.complete(0, uint16(len(leafData)), cfg)
		return
	}

	// Otherwise, there will be some overflow.

	// The full layer's width is the greatest power of two
	// that is less than the number of leaves.
	fullLayerWidth := uint16(1 << (bits.Len16(t.nLeaves) - 1))

	// Whatever number of leaves that won't fit,
	// we have to double that number
	// so that we can use pairs of nodes.
	overflow := 2 * (t.nLeaves - fullLayerWidth)

	// Overflow leaves get written first.
	for i, leaf := range leafData[len(leafData)-int(overflow):] {
		binary.BigEndian.PutUint16(lc.LeafIndex[:], uint16(len(leafData)-int(overflow)+i))
		h.Leaf(leaf, lc, t.nodes[i][:0])
	}

	// Then write the earlier leaves.
	for i, leaf := range leafData[:len(leafData)-int(overflow)] {
		binary.BigEndian.PutUint16(lc.LeafIndex[:], uint16(i))
		h.Leaf(leaf, lc, t.nodes[int(overflow)+i][:0])
	}

	nc := NodeContext{
		Nonce: cfg.Nonce,
	}
	for i := uint16(0); i < overflow/2; i++ {
		leftIdx := uint16(len(leafData)) - overflow + i + i // Two adds might be faster than a multiply.
		rightIdx := leftIdx + 1
		binary.BigEndian.PutUint16(nc.FirstLeafIndex[:], leftIdx)
		binary.BigEndian.PutUint16(nc.LastLeafIndex[:], rightIdx)
		h.Node(t.nodes[2*i], t.nodes[(2*i)+1], nc, t.nodes[len(leafData)+int(i)][:0])
	}

	t.complete(uint(overflow), fullLayerWidth, cfg)
}

// complete reads the row of nodes starting at readStartIdx and of width layerWidth,
// merging them pairwise, left to right,
// and storing the results starting at writeIdx.
func (t *Tree) complete(readStartIdx uint, layerWidth uint16, cfg PopulateConfig) {
	writeIdx := readStartIdx + uint(layerWidth)

	if layerWidth&(layerWidth-1) != 0 {
		panic(fmt.Errorf(
			"BUG: cannot complete binary tree with bottom width %d (must be a power of 2)",
			layerWidth,
		))
	}

	h := cfg.Hasher
	nc := NodeContext{
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

	for layerWidth > 1 {
		// Tracking for leaf spans.
		// Required for proper node hashes.
		spanStart := uint16(0)

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
			writeIdx++

			spanStart = lastLeafIdx + 1
		}

		// Updates for next layer.
		readStartIdx += uint(layerWidth)
		layerWidth >>= 1

		overflowNodeStart >>= 1
		spanWidth <<= 1
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
