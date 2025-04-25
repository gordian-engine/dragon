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

	proofCutoffTier uint8
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

		proofCutoffTier: cfg.ProofCutoffTier,
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

		rootIdxStart += sz
		sz <<= 1
		writeIdx -= sz
	}

	if writeIdx < 0 && rootIdxStart < len(rootProofs) {
		// This indirectly indicates that we had overflow leaves.
		// They are at the end of the given rootProofs,
		// but they are at the start of the nodes.
		n := copy(pt.nodes, rootProofs[rootIdxStart:])

		pt.haveNodes.FlipRange(0, uint(n))
	}

	return pt
}

// HaveLeaves returns the bitset indicating the indices of which leaves
// have been successfully added to the partial tree.
//
// This is a direct reference to the underlying bit set,
// so it must not be modified,
// and it must not be read concurrently with calls to other methods on t.
func (t *PartialTree) HaveLeaves() *bitset.BitSet {
	return t.haveLeaves
}

// Clone returns a newly allocated clone of t.
//
// Since cbmt is an internal package,
// we are only using the Clone method as a temporary measure.
// The actual issue is that during the breathcast relay operation,
// the main loop owns the primary PartialTree instance;
// but verifying a new leaf may require too much work.
// Therefore we want to verify a new leaf on a separate goroutine.
//
// Ideally, the separate work would involve much less allocation.
// This should be possible by walking the existing partial tree
// and collecting any (now-immutable) existing nodes
// along the leaf's proof path,
// and providing that subset of proofs to the other goroutine.
// But that starts to get into the subtle implementation details
// of the partial tree, so instead,
// we just clone the original tree in order for the other goroutine
// to add the leaf directly,
// and then the main loop can use the updated clone
// to merge the result into the primary partial tree.
func (t *PartialTree) Clone() *PartialTree {
	c := &PartialTree{
		haveNodes:  t.haveNodes.Clone(),
		haveLeaves: t.haveLeaves.Clone(),

		nLeaves:  t.nLeaves,
		hasher:   t.hasher,
		hashSize: t.hashSize,

		// The nonce is intended to be immutable,
		// so directly referencing it should be safe.
		nonce: t.nonce,
	}

	// Now the nodes are a little more complicated.
	// Existing nodes are immutable,
	// so we will reference those directly
	// (which end up referencing the primary tree's underlying byte slice for nodes).
	// Nodes that haven't been set yet are allocated directly here.

	missingMem := make([]byte, t.hashSize*(len(t.nodes)-int(t.haveNodes.Count())))
	var missingIdx int

	nodes := make([][]byte, len(t.nodes))
	for i := range nodes {
		if t.haveNodes.Test(uint(i)) {
			// Parent tree has the node, so borrow that slice.
			nodes[i] = t.nodes[i]
		} else {
			// We may end up writing to this node,
			// so it needs to be backed up by our missingMem slice.
			end := missingIdx + t.hashSize
			nodes[i] = missingMem[missingIdx:end]
			missingIdx = end
		}
	}
	c.nodes = nodes

	return c
}

// MergeFrom merges new data from src into t.
// The src value must have been created through [*PartialTree.Clone] on t.
//
// src is destructively updated during MergeFrom,
// and it must not be used again until
// calling [*PartialTree.WriteTo] with src as the dst argument.
func (t *PartialTree) MergeFrom(src *PartialTree) {
	// One quick sanity check to avoid possible bugs.
	// The root proof is always the last node,
	// so if that slice isn't pointing at the exact same location in memory,
	// these cannot be matched properly.
	if len(t.nodes) != len(src.nodes) || !bytes.Equal(t.nodes[len(t.nodes)-1], src.nodes[len(src.nodes)-1]) {
		panic(fmt.Errorf(
			"BUG: attempted to MergeFrom a non-cloned source; dst root hash=%x, src root hash=%x",
			t.nodes[len(t.nodes)-1], src.nodes[len(src.nodes)-1],
		))
	}

	// The trees look like they match, so there are two things to do.
	// First, the easier one, update t.haveLeaves.
	t.haveLeaves.InPlaceUnion(src.haveLeaves)

	// Now the more subtle part.
	// Do an in-place destructive update of the source,
	// to figure out exactly which nodes are new.
	src.haveNodes.InPlaceDifference(t.haveNodes)

	// Now iterate the nodes that t didn't have,
	// so we can copy those node values into t.
	for u, ok := src.haveNodes.NextSet(0); ok; u, ok = src.haveNodes.NextSet(u + 1) {
		copy(t.nodes[int(u)], src.nodes[int(u)])
	}

	// Finally, update t.haveNodes.
	// We could have set these bit-by-bit in the previous loop,
	// but it seems more efficient to do word-by-word this way.
	t.haveNodes.InPlaceUnion(src.haveNodes)
}

// ResetClone resets a previously created clone to match the current state of t.
//
// [*PartialTree.MergeFrom] destructively updates the state of a clone,
// and ResetClone brings the clone back to a synchronized state.
// This is intended to be used in the main loop of RelayOperation,
// until the PartialTree type is refactor for more allocation-friendly
// leaf updates happening outside the relay operation main loop.
func (t *PartialTree) ResetClone(dst *PartialTree) {
	// Basically the same sanity check as MergeFrom.
	if len(t.nodes) != len(dst.nodes) || !bytes.Equal(t.nodes[len(t.nodes)-1], dst.nodes[len(dst.nodes)-1]) {
		panic(fmt.Errorf(
			"BUG: attempted to ResetClone to a non-cloned dest; src root hash=%x, dst root hash=%x",
			t.nodes[len(t.nodes)-1], dst.nodes[len(dst.nodes)-1],
		))
	}

	// The clone had previous allocations for any missing nodes
	// at the time that the clone was created.
	// So for the nodes that t has, we can just update
	// the clone's nodes to point at t's nodes.
	// This means we will not be referencing some parts
	// of the clone's backing memory, but that's fine.
	// It should be better to just sit on the chunk of allocated memory
	// than to keep re-allocating for smaller slices.
	//
	// If we were tracking the length of the root proofs,
	// we could avoid re-assigning that chunk.
	// But at that point we should do the proper refactor to avoid cloning at all.
	for u, ok := t.haveNodes.NextSet(0); ok; u, ok = t.haveNodes.NextSet(u + 1) {
		dst.nodes[int(u)] = t.nodes[int(u)]
	}
	_ = t.haveNodes.Copy(dst.haveNodes)
	_ = t.haveLeaves.Copy(dst.haveLeaves)
}

// HasLeaf reports whether the given leaf has already been added to the tree
// via [*PartialTree.AddLeaf].
//
// HasLeaf reports false if idx is out of bounds.
func (t *PartialTree) HasLeaf(idx uint16) bool {
	return t.haveLeaves.Test(uint(idx))
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
	// First identify spillover leaves and overflow nodes.
	// As a reminder, for a tree like this:
	//
	//   01234
	//   01 234
	//   0 1 2 34
	//   x x x x x x 3 4
	//
	// Leaves 3 and 4 are "spillover" leaves because they didn't fit into
	// the width-four, power-of-two layer.
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
		// We do have an overflow leaf index.
		fullLayerWidth = uint16(1 << (bits.Len16(t.nLeaves) - 1))
		overflowNodeCount := t.nLeaves - fullLayerWidth
		spilloverLeafCount = 2 * overflowNodeCount
		firstSpilloverLeafIdx = t.nLeaves - spilloverLeafCount

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

	// We have at least one proof.
	if leafIdx == firstSpilloverLeafIdx-1 && ((leafIdx & 1) == 0) {
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

		// We do have spillover leaves.
		// Just Len16(t.nLeaves) would be the virtual width of the spillover layer,
		// one less would be the first full layer,
		// so one less than that is the next layer.
		layerWidth = uint16(1) << ((bits.Len16(t.nLeaves)) - 2)
		layerStartNodeIdx = int(spilloverLeafCount) + (1 << (bits.Len16(t.nLeaves) - 1))
		curNodeOffset = int(leafIdx >> 1)
	} else {
		// Spillover and normal leaves are handled nearly the same.
		sib := sibling{
			Hash: proofs[0],
		}
		proofs = proofs[1:]

		// Our even-odd check depends on spillover or normal leaf.
		isSpillover := leafIdx >= firstSpilloverLeafIdx
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
				sib.LeafEnd = sibLeafIdx
				if sibLeafIdx == firstSpilloverLeafIdx {
					// Normally nodes at this layer cover one leaf,
					// but this is a particular case where the self leaf is not overflow,
					// but the sibling is.
					sib.LeafEnd++
				}
			}
		}

		siblings = append(siblings, sib)

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
		if t.haveNodes.Test(uint(layerStartNodeIdx + curNodeOffset)) {
			// We've encountered a hash we already trust,
			// so we don't need to accumulate any more siblings.
			expectedProofHash = t.nodes[layerStartNodeIdx+curNodeOffset]
			break
		}

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

		// The number of full bottom layer nodes we have to account for.
		// At least one of these is worth only one leaf,
		// but depending on the tree shape (i.e. if there was spillover),
		// some may be worth two leaves.
		nodesAlreadyConsumed := sibOffset * spanWidth

		// Track how many normal nodes we've used up.
		// If we've exceeded this, then all other nodes we cover are worth two.
		normalNodesRemaining := normalLeafCount

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
			binary.BigEndian.PutUint16(nc.FirstLeafIndex[:], sib.LeafStart)
			t.hasher.Node(sib.Hash, curHash, nc, hashDst)
		} else {
			binary.BigEndian.PutUint16(nc.LastLeafIndex[:], sib.LeafEnd)
			t.hasher.Node(curHash, sib.Hash, nc, hashDst)
		}
	}

	if !bytes.Equal(
		discoveredHashes[len(discoveredHashes)-t.hashSize:],
		expectedProofHash,
	) {
		return fmt.Errorf(
			"AddLeaf: hash mismatch: calculated %x, expected %x",
			discoveredHashes[len(discoveredHashes)-t.hashSize:],
			expectedProofHash,
		)
	}

	// The final hash matches the expected;
	// recall that we have one more discovered hash than siblings.
	// The final hash doesn't pair with a sibling proof,
	// so all the other hashes and their sibling hashes
	// now get stored in t.nodes.
	t.haveLeaves.Set(uint(leafIdx))

	for i, sib := range siblings {
		var discoveredNodeIdx int
		if sib.IsLeft {
			discoveredNodeIdx = sib.NodeIdx + 1
		} else {
			discoveredNodeIdx = sib.NodeIdx - 1
		}

		hashOffset := i * t.hashSize
		if !t.haveNodes.Test(uint(discoveredNodeIdx)) {
			// It is possible we are working from a clone.
			// In cloned partial trees, we must not write to nodes we already "have",
			// as those slices are still referenced by the original,
			// and another goroutine may be reading that slice at any time.
			copy(t.nodes[discoveredNodeIdx], discoveredHashes[hashOffset:hashOffset+t.hashSize])

			// But we do still have to mark the node in our bitset,
			// because the bitset difference determines how nodes are merged.
			t.haveNodes.Set(uint(discoveredNodeIdx))
		}

		// Then also set the sibling's node details.
		if !t.haveNodes.Test(uint(sib.NodeIdx)) {
			// Same rationale as above.
			copy(t.nodes[sib.NodeIdx], sib.Hash)
			t.haveNodes.Set(uint(sib.NodeIdx))
		}
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

// CompleteResult is the return value from [*PartialTree.Complete].
//
// The input to Complete is a slice of the leaf data
// that has not been added, in the correct order.
// The Proofs field on CompleteResult match that same order.
type CompleteResult struct {
	Proofs [][][]byte
}

// Complete uses the slice of missed leaves
// to fill in all missing hashes in the partial tree.
//
// Normally callers would use [*PartialTree.AddLeaf],
// providing proofs with each leaf;
// but in this code path, we have received enough chunks
// to reconstitute the original data without corresponding proofs.
//
// The missedLeaves input must be preconfirmed to be correct.
// Hashes are calculated up until encountering already-confirmed hashes.
// Upon mismatch, Complete panics.
func (t *PartialTree) Complete(missedLeaves [][]byte) CompleteResult {
	// Confirm the input is the right count.
	expMissedCount := int(t.nLeaves) - int(t.haveLeaves.Count())
	if len(missedLeaves) != expMissedCount {
		panic(fmt.Errorf(
			"BUG: have %d missed leaves but provided %d",
			expMissedCount, len(missedLeaves),
		))
	}

	if len(missedLeaves) == 0 {
		panic(errors.New(
			"BUG: Complete called with zero missed leaves",
		))
	}

	// Similar to [*Tree.Populate], we want to fill in the bottom row first.
	// So we have to determine whether we are dealing with spillover nodes.
	firstSpilloverLeafIdx := t.nLeaves
	var spilloverLeafCount, overflowNodeCount uint16
	var fullLayerWidth uint16
	if t.nLeaves&(t.nLeaves-1) == 0 {
		// The leaves are a power of two.
		fullLayerWidth = t.nLeaves
	} else {
		// We have overflow.
		fullLayerWidth = uint16(1 << (bits.Len16(t.nLeaves) - 1))
		overflowNodeCount = t.nLeaves - fullLayerWidth
		spilloverLeafCount = 2 * overflowNodeCount
		firstSpilloverLeafIdx = t.nLeaves - spilloverLeafCount
	}

	// When we already have a hash, but we have to confirm it,
	// write to this temporary value.
	tmpHash := make([]byte, t.hashSize)

	lc := bcmerkle.LeafContext{
		Nonce: t.nonce,
	}
	var mi int
	// Traverse the missing leaves through the bitset.
	for u, ok := t.haveLeaves.NextClear(0); ok; u, ok = t.haveLeaves.NextClear(u + 1) {
		var nodeIdxForLeaf int
		leafIdx := uint16(u)
		if leafIdx < firstSpilloverLeafIdx {
			nodeIdxForLeaf = int(leafIdx) + int(spilloverLeafCount)
		} else {
			nNormalLeaves := int(fullLayerWidth) - int(overflowNodeCount)
			nodeIdxForLeaf = int(leafIdx) - nNormalLeaves
		}

		// If we already had the hash for this leaf by way of a proof,
		// confirm the new calculated value matches what the proof had.
		checkLeafHash := t.haveNodes.Test(uint(nodeIdxForLeaf))
		if checkLeafHash {
			copy(tmpHash, t.nodes[nodeIdxForLeaf])
		}

		// Hash the leaf and store it directly in t.nodes,
		// which was fully allocated at initialization.
		binary.BigEndian.PutUint16(lc.LeafIndex[:], uint16(u))
		t.hasher.Leaf(missedLeaves[mi], lc, t.nodes[nodeIdxForLeaf][:0])

		if checkLeafHash && !bytes.Equal(tmpHash, t.nodes[nodeIdxForLeaf]) {
			panic(fmt.Errorf(
				"FATAL: calculated leaf hash %x (leaf index %d) differed from hash (index %d) used for earlier calculated proof %x\nleaf content: %x",
				t.nodes[nodeIdxForLeaf], u, nodeIdxForLeaf, tmpHash, missedLeaves[mi],
			))
		}

		mi++
	}

	// We're going to hash nodes from here on out.
	nc := bcmerkle.NodeContext{
		Nonce: t.nonce,
	}

	// Now the leaves are filled in.
	// We need one special treatment for any overflow nodes.
	for i := range overflowNodeCount {
		// If we are in this loop then we do have overflow nodes.

		// First, were we missing either leaf for the overflow node?
		// (Overflow nodes always have two spillover children.)
		leftLeafIdx := firstSpilloverLeafIdx + (i * 2)
		rightLeafIdx := leftLeafIdx + 1

		if t.haveLeaves.Test(uint(leftLeafIdx)) && t.haveLeaves.Test(uint(rightLeafIdx)) {
			// We already had the leaves, so we had to already have the overflow node.
			// Nothing to do for this overflow node.
			continue
		}

		overflowNodeIdx := i + t.nLeaves

		// We were missing at least one leaf,
		// so calculate the expected hash now.
		binary.BigEndian.PutUint16(nc.FirstLeafIndex[:], leftLeafIdx)
		binary.BigEndian.PutUint16(nc.LastLeafIndex[:], rightLeafIdx)

		// The overflow nodes are right at the beginning of the node slice.
		leftChildNodeIdx := i * 2
		rightChildNodeIdx := leftChildNodeIdx + 1

		// If we already had the node,
		// we must not overwrite the node,
		// as a clone on another goroutine could be reading it.
		alreadyHadNode := t.haveNodes.Test(uint(overflowNodeIdx))
		var dst []byte
		if alreadyHadNode {
			dst = tmpHash[:0]
		} else {
			dst = t.nodes[overflowNodeIdx][:0]
		}

		t.hasher.Node(
			t.nodes[leftChildNodeIdx], t.nodes[rightChildNodeIdx],
			nc,
			dst,
		)

		if alreadyHadNode && !bytes.Equal(tmpHash, t.nodes[overflowNodeIdx]) {
			panic(fmt.Errorf(
				"FATAL: calculated overflow node hash %x differed from hash used for earlier calculated proof %x",
				t.nodes[overflowNodeIdx], tmpHash,
			))
		}
	}

	// At this point we have fully populated the bottom full layer.
	// It is fully correct based on the information we have:
	// existing leaves already had confirmed proofs,
	// and new spillover leaves have calculated overflow nodes.
	// If we already had proof of those particular overflow nodes,
	// the new hash matched the one we saw before.
	//
	// From here, we are going to iterate from that full layer towards the root.
	// On the current layer, we have already confirmed the node
	// with the information we have.
	// We are going to inspect the t.haveNodes bitset on the current layer.
	// Based on which nodes we were missing prior to entering t.Complete,
	// we will fill in the parent nodes.
	// If we already had the parent node, we simply confirm it matches.
	// If we didn't have the parent node, we fill it in.
	//
	// Iteration ends when we reach a current row where every element
	// already had a set bit in t.haveNodes.

	layerStart := uint(t.nLeaves) + uint(overflowNodeCount)
	layerWidth := uint(fullLayerWidth)
	parentLayerStart := layerStart + layerWidth
	nodeSpan := uint(2) // Each non-overflow node in the current row is worth this many nodes in the bottom layer.
	for layerWidth > 1 {
		if t.haveNodes.OnesBetween(layerStart, layerWidth+1) == layerWidth {
			// We already had all the nodes in the current row.
			// Nothing left to do in this loop.
			break
		}

		// First we need to identify which nodes in the current row we missed.
		for u, ok := t.haveNodes.NextClear(layerStart); ok && u < layerStart+layerWidth; u, ok = t.haveLeaves.NextClear(u + 1) {
			left := u - uint(layerStart)
			if (left & 1) == 1 {
				// Force the left node to be even.
				left--
			} else {
				// We did match the left even node,
				// but make sure the next loop iteration doesn't match the sibling.
				u++
			}

			// Calculate the start leaf coverage for the node context.
			normalLeavesRemaining := int(t.nLeaves) - int(overflowNodeCount)
			wantNodes := int(nodeSpan) * int(left)
			var leafStart uint16

			if wantNodes <= normalLeavesRemaining {
				normalLeavesRemaining -= wantNodes
				leafStart = uint16(wantNodes) * uint16(nodeSpan)
			} else {
				leafStart = uint16(normalLeavesRemaining) * uint16(nodeSpan)

				wantNodes -= normalLeavesRemaining
				normalLeavesRemaining = 0

				leafStart += uint16(wantNodes) * 2 * uint16(nodeSpan)
			}
			binary.BigEndian.PutUint16(nc.FirstLeafIndex[:], leafStart)

			// Now account for the end leaf.
			wantNodes = int(nodeSpan) * 2
			leafEnd := leafStart
			if wantNodes <= normalLeavesRemaining {
				leafEnd += uint16(wantNodes) * uint16(nodeSpan)
			} else {
				leafEnd += uint16(normalLeavesRemaining) * uint16(nodeSpan)

				wantNodes -= normalLeavesRemaining

				leafEnd += uint16(wantNodes) * 2 * uint16(nodeSpan)
			}
			binary.BigEndian.PutUint16(nc.LastLeafIndex[:], leafEnd)

			parentNodeIdx := parentLayerStart + (left >> 1)
			haveParent := t.haveNodes.Test(parentNodeIdx)
			if haveParent {
				copy(tmpHash, t.nodes[parentNodeIdx])
			}

			t.hasher.Node(
				t.nodes[left], t.nodes[left+1],
				nc,
				t.nodes[parentNodeIdx][:0],
			)

			if haveParent && !bytes.Equal(tmpHash, t.nodes[parentNodeIdx]) {
				panic(fmt.Errorf(
					"FATAL: calculated node hash %x covering leaves [%d, %d] differed from earlier proof %x",
					t.nodes[parentNodeIdx],
					// Use the node context so we don't continue referencing
					// the two uint16 literals.
					binary.BigEndian.Uint16(nc.FirstLeafIndex[:]),
					binary.BigEndian.Uint16(nc.LastLeafIndex[:]),
					tmpHash,
				))
			}
		}

		// We have filled in everything in the parent row,
		// so now bookkeeping for the next iteration.
		layerStart += layerWidth
		layerWidth >>= 1
		parentLayerStart += layerWidth
		nodeSpan <<= 1
	}

	return t.complete(len(missedLeaves))
}

// complete returns the actual CompleteResult,
// based on a fully populated set of nodes from [*PartialTree.Complete].
func (t *PartialTree) complete(n int) CompleteResult {
	proofs := make([][][]byte, n)

	treeHeight := uint8(bits.Len16(t.nLeaves))
	normalProofLen := treeHeight - t.proofCutoffTier - 1

	firstSpilloverLeafIdx := t.nLeaves
	var fullLayerWidth uint16
	var fullLayerStart uint
	if t.nLeaves&(t.nLeaves-1) == 0 {
		// The leaves are a power of two.
		fullLayerWidth = t.nLeaves
	} else {
		// We have overflow, so the first spillover index
		// will actually be somewhere in the leaves.
		fullLayerWidth = uint16(1 << (bits.Len16(t.nLeaves) - 1))
		overflowNodeCount := t.nLeaves - fullLayerWidth
		spilloverLeafCount := 2 * overflowNodeCount
		firstSpilloverLeafIdx = t.nLeaves - spilloverLeafCount
		fullLayerStart = uint(spilloverLeafCount)
	}

	resIdx := 0
	for u, ok := t.haveLeaves.NextClear(0); ok; u, ok = t.haveLeaves.NextClear(u + 1) {
		var allLeafProofs, leafProofs [][]byte
		var curLayerOffset uint
		if u < uint(firstSpilloverLeafIdx) {
			if normalProofLen > 0 {
				allLeafProofs = make([][]byte, normalProofLen)
				leafProofs = allLeafProofs
			}
			curLayerOffset = u
		} else {
			allLeafProofs = make([][]byte, normalProofLen+1)
			leafProofs = allLeafProofs[1:]

			// Since this is a spillover leaf,
			// we will fill in allLeafProofs first.
			nodeIdx := u - uint(firstSpilloverLeafIdx)
			if (nodeIdx & 1) == 1 {
				// Odd leaf, use left sibling.
				allLeafProofs[0] = t.nodes[nodeIdx-1]
			} else {
				// Even leaf, use right sibling.
				allLeafProofs[0] = t.nodes[nodeIdx+1]
			}

			curLayerOffset = uint(firstSpilloverLeafIdx) + (uint(nodeIdx) >> 1)
		}

		width := fullLayerWidth
		layerStart := fullLayerStart
		for i := range leafProofs {
			nodeIdx := layerStart + curLayerOffset

			if (nodeIdx & 1) == 1 {
				leafProofs[i] = t.nodes[nodeIdx-1]
			} else {
				leafProofs[i] = t.nodes[nodeIdx+1]
			}

			// Bookkeeping.
			layerStart += uint(width)
			width >>= 1
			curLayerOffset >>= 1
		}

		// Bookkeeping.
		proofs[resIdx] = allLeafProofs
		resIdx++
	}

	return CompleteResult{
		Proofs: proofs,
	}
}
