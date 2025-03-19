package cbmt_test

import (
	"crypto/sha256"
	"hash/fnv"
	"testing"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/stretchr/testify/require"
)

// All the "_simplified_" tests in this file use the fnv32Hasher,
// which makes for simple tests but does not exercise the left/rightness
// of the hash functions.
//
// See the "_context_" tests for exercising the context values with the hasher.

func TestTree_Populate_simplified_2_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(2, 4)

	leaves := [][]byte{
		[]byte("hello"),
		[]byte("world"),
	}

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: fnv32Hasher{},
	})

	expLeaf0 := fnv32Hash("hello")
	require.Equal(t, expLeaf0, tree.Leaf(0))

	expLeaf1 := fnv32Hash("world")
	require.Equal(t, expLeaf1, tree.Leaf(1))

	expRoot := fnv32Hash(string(expLeaf0) + string(expLeaf1))
	require.Equal(t, expRoot, res.RootProof[0])
}

func TestTree_Populate_simplified_4_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(4, 4)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	}

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: fnv32Hasher{},
	})

	expLeaf0 := fnv32Hash("zero")
	require.Equal(t, expLeaf0, tree.Leaf(0))

	expLeaf1 := fnv32Hash("one")
	require.Equal(t, expLeaf1, tree.Leaf(1))

	expLeaf2 := fnv32Hash("two")
	require.Equal(t, expLeaf2, tree.Leaf(2))

	expLeaf3 := fnv32Hash("three")
	require.Equal(t, expLeaf3, tree.Leaf(3))

	expNode01 := fnv32Hash(string(expLeaf0) + string(expLeaf1))
	expNode23 := fnv32Hash(string(expLeaf2) + string(expLeaf3))

	expRoot := fnv32Hash(string(expNode01) + string(expNode23))
	require.Equal(t, expRoot, res.RootProof[0])
}

func TestTree_Populate_simplified_3_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(3, 4)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
	}

	/* Tree structure:

	012
	0 12
	x 1 2

	*/

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: fnv32Hasher{},
	})

	expLeaf0 := fnv32Hash("zero")
	require.Equal(t, expLeaf0, tree.Leaf(0))

	expLeaf1 := fnv32Hash("one")
	require.Equal(t, expLeaf1, tree.Leaf(1))

	expLeaf2 := fnv32Hash("two")
	require.Equal(t, expLeaf2, tree.Leaf(2))

	expNode12 := fnv32Hash(string(expLeaf1) + string(expLeaf2))

	expRoot := fnv32Hash(string(expLeaf0) + string(expNode12))

	require.Equal(t, [][]byte{
		expRoot,
	}, res.RootProof)

	require.Equal(t, [][]byte{
		expNode12,
	}, res.Proofs[0])

	require.Equal(t, [][]byte{
		expLeaf2,
		expLeaf0,
	}, res.Proofs[1])

	require.Equal(t, [][]byte{
		expLeaf1,
		expLeaf0,
	}, res.Proofs[2])
}

func TestTree_Populate_simplified_5_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(5, 4)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
		[]byte("four"),
	}

	/* Tree structure:

	01234
	01 234
	0 1 2 34
	x x x 3 4

	*/

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: fnv32Hasher{},
	})

	expLeaf0 := fnv32Hash("zero")
	require.Equal(t, expLeaf0, tree.Leaf(0))

	expLeaf1 := fnv32Hash("one")
	require.Equal(t, expLeaf1, tree.Leaf(1))

	expLeaf2 := fnv32Hash("two")
	require.Equal(t, expLeaf2, tree.Leaf(2))

	expLeaf3 := fnv32Hash("three")
	require.Equal(t, expLeaf3, tree.Leaf(3))

	expLeaf4 := fnv32Hash("four")
	require.Equal(t, expLeaf4, tree.Leaf(4))

	expNode34 := fnv32Hash(string(expLeaf3) + string(expLeaf4))

	expNode01 := fnv32Hash(string(expLeaf0) + string(expLeaf1))
	expNode234 := fnv32Hash(string(expLeaf2) + string(expNode34))

	expRoot := fnv32Hash(string(expNode01) + string(expNode234))

	require.Equal(t, [][]byte{
		expRoot,
	}, res.RootProof)

	require.Equal(t, [][]byte{
		expLeaf1,
		expNode234,
	}, res.Proofs[0])

	require.Equal(t, [][]byte{
		expLeaf0,
		expNode234,
	}, res.Proofs[1])

	require.Equal(t, [][]byte{
		expNode34,
		expNode01,
	}, res.Proofs[2])

	require.Equal(t, [][]byte{
		expLeaf4,
		expLeaf2,
		expNode01,
	}, res.Proofs[3])

	require.Equal(t, [][]byte{
		expLeaf3,
		expLeaf2,
		expNode01,
	}, res.Proofs[4])

	// This outer test, with a non-power-of-2, was chosen arbitrarily for a high cutoff subtest.
	t.Run("high proof cutoff tier", func(t *testing.T) {
		res = tree.Populate(leaves, cbmt.PopulateConfig{
			Hasher: fnv32Hasher{},

			// Tier too high, so no leaves will have proofs.
			ProofCutoffTier: 8,
		})

		require.Equal(t, [][]byte{
			expRoot,
			expNode01, expNode234,
			expLeaf0, expLeaf1, expLeaf2, expNode34,
			expLeaf3, expLeaf4,
		}, res.RootProof)
	})

	// This covers a particular edge case with filling in proofs for overflow nodes.
	t.Run("partial proof cutoff tier", func(t *testing.T) {
		res = tree.Populate(leaves, cbmt.PopulateConfig{
			Hasher: fnv32Hasher{},

			ProofCutoffTier: 1,
		})

		require.Equal(t, [][]byte{
			expRoot,
			expNode01, expNode234,
		}, res.RootProof)

		require.Equal(t, [][]byte{
			expLeaf1,
		}, res.Proofs[0])

		require.Equal(t, [][]byte{
			expLeaf0,
		}, res.Proofs[1])

		require.Equal(t, [][]byte{
			expNode34,
		}, res.Proofs[2])

		require.Equal(t, [][]byte{
			expLeaf4,
			expLeaf2,
		}, res.Proofs[3])

		require.Equal(t, [][]byte{
			expLeaf3,
			expLeaf2,
		}, res.Proofs[4])
	})
}

func TestTree_Populate_simplified_6_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(6, 4)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
		[]byte("four"),
		[]byte("five"),
	}

	/* Tree structure:

	012345
	01 2345
	0 1 23 45
	x x x  x  2 3 4 5

	*/

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: fnv32Hasher{},
	})

	expLeaf0 := fnv32Hash("zero")
	require.Equal(t, expLeaf0, tree.Leaf(0))

	expLeaf1 := fnv32Hash("one")
	require.Equal(t, expLeaf1, tree.Leaf(1))

	expLeaf2 := fnv32Hash("two")
	require.Equal(t, expLeaf2, tree.Leaf(2))

	expLeaf3 := fnv32Hash("three")
	require.Equal(t, expLeaf3, tree.Leaf(3))

	expLeaf4 := fnv32Hash("four")
	require.Equal(t, expLeaf4, tree.Leaf(4))

	expLeaf5 := fnv32Hash("five")
	require.Equal(t, expLeaf5, tree.Leaf(5))

	expNode23 := fnv32Hash(string(expLeaf2) + string(expLeaf3))
	expNode45 := fnv32Hash(string(expLeaf4) + string(expLeaf5))
	expNode2345 := fnv32Hash(string(expNode23) + string(expNode45))

	expNode01 := fnv32Hash(string(expLeaf0) + string(expLeaf1))

	expRoot := fnv32Hash(string(expNode01) + string(expNode2345))

	require.Equal(t, [][]byte{
		expRoot,
	}, res.RootProof)

	require.Equal(t, [][]byte{
		expLeaf1,
		expNode2345,
	}, res.Proofs[0])

	require.Equal(t, [][]byte{
		expLeaf0,
		expNode2345,
	}, res.Proofs[1])

	require.Equal(t, [][]byte{
		expLeaf3,
		expNode45,
		expNode01,
	}, res.Proofs[2])

	require.Equal(t, [][]byte{
		expLeaf2,
		expNode45,
		expNode01,
	}, res.Proofs[3])

	require.Equal(t, [][]byte{
		expLeaf5,
		expNode23,
		expNode01,
	}, res.Proofs[4])

	require.Equal(t, [][]byte{
		expLeaf4,
		expNode23,
		expNode01,
	}, res.Proofs[5])
}

func TestTree_Populate_simplified_7_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(7, 4)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
		[]byte("four"),
		[]byte("five"),
		[]byte("six"),
	}

	/* Tree structure:

	0123456
	012 3456
	0 12 34 56
	x x 1 2 3 4 5 6

	*/

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: fnv32Hasher{},
	})

	expLeaf0 := fnv32Hash("zero")
	require.Equal(t, expLeaf0, tree.Leaf(0))

	expLeaf1 := fnv32Hash("one")
	require.Equal(t, expLeaf1, tree.Leaf(1))

	expLeaf2 := fnv32Hash("two")
	require.Equal(t, expLeaf2, tree.Leaf(2))

	expLeaf3 := fnv32Hash("three")
	require.Equal(t, expLeaf3, tree.Leaf(3))

	expLeaf4 := fnv32Hash("four")
	require.Equal(t, expLeaf4, tree.Leaf(4))

	expLeaf5 := fnv32Hash("five")
	require.Equal(t, expLeaf5, tree.Leaf(5))

	expLeaf6 := fnv32Hash("six")
	require.Equal(t, expLeaf6, tree.Leaf(6))

	expNode34 := fnv32Hash(string(expLeaf3) + string(expLeaf4))
	expNode56 := fnv32Hash(string(expLeaf5) + string(expLeaf6))
	expNode3456 := fnv32Hash(string(expNode34) + string(expNode56))

	expNode12 := fnv32Hash(string(expLeaf1) + string(expLeaf2))
	expNode012 := fnv32Hash(string(expLeaf0) + string(expNode12))

	expRoot := fnv32Hash(string(expNode012) + string(expNode3456))

	require.Equal(t, [][]byte{
		expRoot,
	}, res.RootProof)

	require.Equal(t, [][]byte{
		expNode12,
		expNode3456,
	}, res.Proofs[0])

	require.Equal(t, [][]byte{
		expLeaf2,
		expLeaf0,
		expNode3456,
	}, res.Proofs[1])

	require.Equal(t, [][]byte{
		expLeaf1,
		expLeaf0,
		expNode3456,
	}, res.Proofs[2])

	require.Equal(t, [][]byte{
		expLeaf4,
		expNode56,
		expNode012,
	}, res.Proofs[3])

	require.Equal(t, [][]byte{
		expLeaf3,
		expNode56,
		expNode012,
	}, res.Proofs[4])

	require.Equal(t, [][]byte{
		expLeaf6,
		expNode34,
		expNode012,
	}, res.Proofs[5])

	require.Equal(t, [][]byte{
		expLeaf5,
		expNode34,
		expNode012,
	}, res.Proofs[6])
}

func TestTree_Populate_simplified_8_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(8, 4)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
		[]byte("four"),
		[]byte("five"),
		[]byte("six"),
		[]byte("seven"),
	}

	pc := cbmt.PopulateConfig{
		Hasher: fnv32Hasher{},

		ProofCutoffTier: 0,
	}
	res := tree.Populate(leaves, pc)

	expLeaf0 := fnv32Hash("zero")
	require.Equal(t, expLeaf0, tree.Leaf(0))

	expLeaf1 := fnv32Hash("one")
	require.Equal(t, expLeaf1, tree.Leaf(1))

	expLeaf2 := fnv32Hash("two")
	require.Equal(t, expLeaf2, tree.Leaf(2))

	expLeaf3 := fnv32Hash("three")
	require.Equal(t, expLeaf3, tree.Leaf(3))

	expLeaf4 := fnv32Hash("four")
	require.Equal(t, expLeaf4, tree.Leaf(4))

	expLeaf5 := fnv32Hash("five")
	require.Equal(t, expLeaf5, tree.Leaf(5))

	expLeaf6 := fnv32Hash("six")
	require.Equal(t, expLeaf6, tree.Leaf(6))

	expLeaf7 := fnv32Hash("seven")
	require.Equal(t, expLeaf7, tree.Leaf(7))

	expNode01 := fnv32Hash(string(expLeaf0) + string(expLeaf1))
	expNode23 := fnv32Hash(string(expLeaf2) + string(expLeaf3))
	expNode0123 := fnv32Hash(string(expNode01) + string(expNode23))

	expNode45 := fnv32Hash(string(expLeaf4) + string(expLeaf5))
	expNode67 := fnv32Hash(string(expLeaf6) + string(expLeaf7))
	expNode4567 := fnv32Hash(string(expNode45) + string(expNode67))

	expRoot := fnv32Hash(string(expNode0123) + string(expNode4567))

	t.Run("proof cutoff = 0", func(t *testing.T) {
		require.Equal(t, [][]byte{
			expRoot,
		}, res.RootProof)

		require.Equal(t, [][]byte{
			expLeaf1,
			expNode23,
			expNode4567,
		}, res.Proofs[0])

		require.Equal(t, [][]byte{
			expLeaf0,
			expNode23,
			expNode4567,
		}, res.Proofs[1])

		require.Equal(t, [][]byte{
			expLeaf3,
			expNode01,
			expNode4567,
		}, res.Proofs[2])

		require.Equal(t, [][]byte{
			expLeaf2,
			expNode01,
			expNode4567,
		}, res.Proofs[3])

		require.Equal(t, [][]byte{
			expLeaf5,
			expNode67,
			expNode0123,
		}, res.Proofs[4])

		require.Equal(t, [][]byte{
			expLeaf4,
			expNode67,
			expNode0123,
		}, res.Proofs[5])

		require.Equal(t, [][]byte{
			expLeaf7,
			expNode45,
			expNode0123,
		}, res.Proofs[6])

		require.Equal(t, [][]byte{
			expLeaf6,
			expNode45,
			expNode0123,
		}, res.Proofs[7])
	})

	t.Run("proof cutoff = 1", func(t *testing.T) {
		pc.ProofCutoffTier = 1
		res = tree.Populate(leaves, pc)

		require.Equal(t, [][]byte{
			expRoot,
			expNode0123, expNode4567,
		}, res.RootProof)

		require.Equal(t, [][]byte{
			expLeaf1,
			expNode23,
		}, res.Proofs[0])

		require.Equal(t, [][]byte{
			expLeaf0,
			expNode23,
		}, res.Proofs[1])

		require.Equal(t, [][]byte{
			expLeaf3,
			expNode01,
		}, res.Proofs[2])

		require.Equal(t, [][]byte{
			expLeaf2,
			expNode01,
		}, res.Proofs[3])

		require.Equal(t, [][]byte{
			expLeaf5,
			expNode67,
		}, res.Proofs[4])

		require.Equal(t, [][]byte{
			expLeaf4,
			expNode67,
		}, res.Proofs[5])

		require.Equal(t, [][]byte{
			expLeaf7,
			expNode45,
		}, res.Proofs[6])

		require.Equal(t, [][]byte{
			expLeaf6,
			expNode45,
		}, res.Proofs[7])
	})

	t.Run("proof cutoff = 2", func(t *testing.T) {
		pc.ProofCutoffTier = 2
		res = tree.Populate(leaves, pc)

		require.Equal(t, [][]byte{
			expRoot,
			expNode0123, expNode4567,
			expNode01, expNode23, expNode45, expNode67,
		}, res.RootProof)

		require.Equal(t, [][]byte{
			expLeaf1,
		}, res.Proofs[0])

		require.Equal(t, [][]byte{
			expLeaf0,
		}, res.Proofs[1])

		require.Equal(t, [][]byte{
			expLeaf3,
		}, res.Proofs[2])

		require.Equal(t, [][]byte{
			expLeaf2,
		}, res.Proofs[3])

		require.Equal(t, [][]byte{
			expLeaf5,
		}, res.Proofs[4])

		require.Equal(t, [][]byte{
			expLeaf4,
		}, res.Proofs[5])

		require.Equal(t, [][]byte{
			expLeaf7,
		}, res.Proofs[6])

		require.Equal(t, [][]byte{
			expLeaf6,
		}, res.Proofs[7])
	})

	// Another arbitrary size choice to exercise an excessive proof cutoff tier.
	t.Run("proof cutoff = 8", func(t *testing.T) {
		pc.ProofCutoffTier = 8
		res = tree.Populate(leaves, pc)

		require.Equal(t, [][]byte{
			expRoot,
			expNode0123, expNode4567,
			expNode01, expNode23, expNode45, expNode67,
			expLeaf0, expLeaf1, expLeaf2, expLeaf3, expLeaf4, expLeaf5, expLeaf6, expLeaf7,
		}, res.RootProof)
	})
}

func TestTree_Populate_simplified_10_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(10, 4)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
		[]byte("four"),
		[]byte("five"),
		[]byte("six"),
		[]byte("seven"),
		[]byte("eight"),
		[]byte("nine"),
	}

	/* Tree structure:

	0123456789A
	0123 456789
	01 23 45 6789
	0 1 2 3 4 5 67 89
	x x x x x x x x x x x x x 6 7 8 9

	*/

	pc := cbmt.PopulateConfig{
		Hasher: fnv32Hasher{},

		ProofCutoffTier: 0,
	}
	res := tree.Populate(leaves, pc)

	expLeaf0 := fnv32Hash("zero")
	require.Equal(t, expLeaf0, tree.Leaf(0))

	expLeaf1 := fnv32Hash("one")
	require.Equal(t, expLeaf1, tree.Leaf(1))

	expLeaf2 := fnv32Hash("two")
	require.Equal(t, expLeaf2, tree.Leaf(2))

	expLeaf3 := fnv32Hash("three")
	require.Equal(t, expLeaf3, tree.Leaf(3))

	expLeaf4 := fnv32Hash("four")
	require.Equal(t, expLeaf4, tree.Leaf(4))

	expLeaf5 := fnv32Hash("five")
	require.Equal(t, expLeaf5, tree.Leaf(5))

	expLeaf6 := fnv32Hash("six")
	require.Equal(t, expLeaf6, tree.Leaf(6))

	expLeaf7 := fnv32Hash("seven")
	require.Equal(t, expLeaf7, tree.Leaf(7))

	expLeaf8 := fnv32Hash("eight")
	require.Equal(t, expLeaf8, tree.Leaf(8))

	expLeaf9 := fnv32Hash("nine")
	require.Equal(t, expLeaf9, tree.Leaf(9))

	expNode67 := fnv32Hash(string(expLeaf6) + string(expLeaf7))
	expNode89 := fnv32Hash(string(expLeaf8) + string(expLeaf9))
	expNode6789 := fnv32Hash(string(expNode67) + string(expNode89))

	expNode01 := fnv32Hash(string(expLeaf0) + string(expLeaf1))
	expNode23 := fnv32Hash(string(expLeaf2) + string(expLeaf3))
	expNode45 := fnv32Hash(string(expLeaf4) + string(expLeaf5))

	expNode0123 := fnv32Hash(string(expNode01) + string(expNode23))
	expNode456789 := fnv32Hash(string(expNode45) + string(expNode6789))

	expRoot := fnv32Hash(string(expNode0123) + string(expNode456789))

	t.Run("proof cutoff = 0", func(t *testing.T) {
		require.Equal(t, [][]byte{
			expRoot,
		}, res.RootProof)

		require.Equal(t, [][]byte{
			expLeaf1,
			expNode23,
			expNode456789,
		}, res.Proofs[0])

		require.Equal(t, [][]byte{
			expLeaf0,
			expNode23,
			expNode456789,
		}, res.Proofs[1])

		require.Equal(t, [][]byte{
			expLeaf3,
			expNode01,
			expNode456789,
		}, res.Proofs[2])

		require.Equal(t, [][]byte{
			expLeaf2,
			expNode01,
			expNode456789,
		}, res.Proofs[3])

		require.Equal(t, [][]byte{
			expLeaf5,
			expNode6789,
			expNode0123,
		}, res.Proofs[4])

		require.Equal(t, [][]byte{
			expLeaf4,
			expNode6789,
			expNode0123,
		}, res.Proofs[5])

		require.Equal(t, [][]byte{
			expLeaf7,
			expNode89,
			expNode45,
			expNode0123,
		}, res.Proofs[6])

		require.Equal(t, [][]byte{
			expLeaf6,
			expNode89,
			expNode45,
			expNode0123,
		}, res.Proofs[7])

		require.Equal(t, [][]byte{
			expLeaf9,
			expNode67,
			expNode45,
			expNode0123,
		}, res.Proofs[8])

		require.Equal(t, [][]byte{
			expLeaf8,
			expNode67,
			expNode45,
			expNode0123,
		}, res.Proofs[9])
	})

	t.Run("proof cutoff = 1", func(t *testing.T) {
		pc.ProofCutoffTier = 1
		res = tree.Populate(leaves, pc)

		require.Equal(t, [][]byte{
			expRoot,
			expNode0123, expNode456789,
		}, res.RootProof)

		require.Equal(t, [][]byte{
			expLeaf1,
			expNode23,
		}, res.Proofs[0])

		require.Equal(t, [][]byte{
			expLeaf0,
			expNode23,
		}, res.Proofs[1])

		require.Equal(t, [][]byte{
			expLeaf3,
			expNode01,
		}, res.Proofs[2])

		require.Equal(t, [][]byte{
			expLeaf2,
			expNode01,
		}, res.Proofs[3])

		require.Equal(t, [][]byte{
			expLeaf5,
			expNode6789,
		}, res.Proofs[4])

		require.Equal(t, [][]byte{
			expLeaf4,
			expNode6789,
		}, res.Proofs[5])

		require.Equal(t, [][]byte{
			expLeaf7,
			expNode89,
			expNode45,
		}, res.Proofs[6])

		require.Equal(t, [][]byte{
			expLeaf6,
			expNode89,
			expNode45,
		}, res.Proofs[7])

		require.Equal(t, [][]byte{
			expLeaf9,
			expNode67,
			expNode45,
		}, res.Proofs[8])

		require.Equal(t, [][]byte{
			expLeaf8,
			expNode67,
			expNode45,
		}, res.Proofs[9])
	})

	t.Run("proof cutoff = 2", func(t *testing.T) {
		pc.ProofCutoffTier = 2
		res = tree.Populate(leaves, pc)

		require.Equal(t, [][]byte{
			expRoot,
			expNode0123, expNode456789,
			expNode01, expNode23, expNode45, expNode6789,
		}, res.RootProof)

		require.Equal(t, [][]byte{
			expLeaf1,
		}, res.Proofs[0])

		require.Equal(t, [][]byte{
			expLeaf0,
		}, res.Proofs[1])

		require.Equal(t, [][]byte{
			expLeaf3,
		}, res.Proofs[2])

		require.Equal(t, [][]byte{
			expLeaf2,
		}, res.Proofs[3])

		require.Equal(t, [][]byte{
			expLeaf5,
		}, res.Proofs[4])

		require.Equal(t, [][]byte{
			expLeaf4,
		}, res.Proofs[5])

		require.Equal(t, [][]byte{
			expLeaf7,
			expNode89,
		}, res.Proofs[6])

		require.Equal(t, [][]byte{
			expLeaf6,
			expNode89,
		}, res.Proofs[7])

		require.Equal(t, [][]byte{
			expLeaf9,
			expNode67,
		}, res.Proofs[8])

		require.Equal(t, [][]byte{
			expLeaf8,
			expNode67,
		}, res.Proofs[9])
	})
}

func TestTree_Populate_simplified_11_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(11, 4)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
		[]byte("four"),
		[]byte("five"),
		[]byte("six"),
		[]byte("seven"),
		[]byte("eight"),
		[]byte("nine"),
		[]byte("ten"),
	}

	/* Tree structure:

	0123456789A
	0123 456789A
	01 23 456 789A
	0 1 2 3 4 56 78 9A
	x x x x x x x x x 5 6 7 8 9 A

	This tree structure is interesting
	because we end up with 2-2-3-4 pairing on the second layer.

	*/

	pc := cbmt.PopulateConfig{
		Hasher: fnv32Hasher{},

		ProofCutoffTier: 0,
	}
	res := tree.Populate(leaves, pc)

	expLeaf0 := fnv32Hash("zero")
	require.Equal(t, expLeaf0, tree.Leaf(0))

	expLeaf1 := fnv32Hash("one")
	require.Equal(t, expLeaf1, tree.Leaf(1))

	expLeaf2 := fnv32Hash("two")
	require.Equal(t, expLeaf2, tree.Leaf(2))

	expLeaf3 := fnv32Hash("three")
	require.Equal(t, expLeaf3, tree.Leaf(3))

	expLeaf4 := fnv32Hash("four")
	require.Equal(t, expLeaf4, tree.Leaf(4))

	expLeaf5 := fnv32Hash("five")
	require.Equal(t, expLeaf5, tree.Leaf(5))

	expLeaf6 := fnv32Hash("six")
	require.Equal(t, expLeaf6, tree.Leaf(6))

	expLeaf7 := fnv32Hash("seven")
	require.Equal(t, expLeaf7, tree.Leaf(7))

	expLeaf8 := fnv32Hash("eight")
	require.Equal(t, expLeaf8, tree.Leaf(8))

	expLeaf9 := fnv32Hash("nine")
	require.Equal(t, expLeaf9, tree.Leaf(9))

	expLeafA := fnv32Hash("ten")
	require.Equal(t, expLeafA, tree.Leaf(10))

	expNode56 := fnv32Hash(string(expLeaf5) + string(expLeaf6))
	expNode78 := fnv32Hash(string(expLeaf7) + string(expLeaf8))
	expNode9A := fnv32Hash(string(expLeaf9) + string(expLeafA))

	expNode456 := fnv32Hash(string(expLeaf4) + string(expNode56))
	expNode789A := fnv32Hash(string(expNode78) + string(expNode9A))
	expNode456789A := fnv32Hash(string(expNode456) + string(expNode789A))

	expNode01 := fnv32Hash(string(expLeaf0) + string(expLeaf1))
	expNode23 := fnv32Hash(string(expLeaf2) + string(expLeaf3))
	expNode0123 := fnv32Hash(string(expNode01) + string(expNode23))

	expRoot := fnv32Hash(string(expNode0123) + string(expNode456789A))

	t.Run("proof cutoff = 0", func(t *testing.T) {
		require.Equal(t, [][]byte{
			expRoot,
		}, res.RootProof)

		require.Equal(t, [][]byte{
			expLeaf1,
			expNode23,
			expNode456789A,
		}, res.Proofs[0])

		require.Equal(t, [][]byte{
			expLeaf0,
			expNode23,
			expNode456789A,
		}, res.Proofs[1])

		require.Equal(t, [][]byte{
			expLeaf3,
			expNode01,
			expNode456789A,
		}, res.Proofs[2])

		require.Equal(t, [][]byte{
			expLeaf2,
			expNode01,
			expNode456789A,
		}, res.Proofs[3])

		require.Equal(t, [][]byte{
			expNode56,
			expNode789A,
			expNode0123,
		}, res.Proofs[4])

		require.Equal(t, [][]byte{
			expLeaf6,
			expLeaf4,
			expNode789A,
			expNode0123,
		}, res.Proofs[5])

		require.Equal(t, [][]byte{
			expLeaf5,
			expLeaf4,
			expNode789A,
			expNode0123,
		}, res.Proofs[6])

		require.Equal(t, [][]byte{
			expLeaf8,
			expNode9A,
			expNode456,
			expNode0123,
		}, res.Proofs[7])

		require.Equal(t, [][]byte{
			expLeaf7,
			expNode9A,
			expNode456,
			expNode0123,
		}, res.Proofs[8])

		require.Equal(t, [][]byte{
			expLeafA,
			expNode78,
			expNode456,
			expNode0123,
		}, res.Proofs[9])

		require.Equal(t, [][]byte{
			expLeaf9,
			expNode78,
			expNode456,
			expNode0123,
		}, res.Proofs[10])
	})
}

func TestTree_Populate_simplified_21_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(21, 4)

	leaves := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
		[]byte("d"),
		[]byte("e"),
		[]byte("f"),
		[]byte("g"),
		[]byte("h"),
		[]byte("i"),
		[]byte("j"),
		[]byte("k"),
		[]byte("l"),
		[]byte("m"),
		[]byte("n"),
		[]byte("o"),
		[]byte("p"),
		[]byte("q"),
		[]byte("r"),
		[]byte("s"),
		[]byte("t"),
		[]byte("u"),
	}

	/* Tree structure:

	abcdefghijklmnopqrstu
	abcdefgh ijklmnopqrstu
	abcd efgh ijklm nopqrstu
	ab cd ef gh ij klm nopq rstu
	a b c d e f g h i j k lm no pq rs tu
	x x x x x x x x x x x l m n o p q r s t u

	*/

	pc := cbmt.PopulateConfig{
		Hasher: fnv32Hasher{},

		ProofCutoffTier: 0,
	}
	res := tree.Populate(leaves, pc)

	expLeafA := fnv32Hash("a")
	require.Equal(t, expLeafA, tree.Leaf(0))

	expLeafB := fnv32Hash("b")
	require.Equal(t, expLeafB, tree.Leaf(1))

	expLeafC := fnv32Hash("c")
	require.Equal(t, expLeafC, tree.Leaf(2))

	expLeafD := fnv32Hash("d")
	require.Equal(t, expLeafD, tree.Leaf(3))

	expLeafE := fnv32Hash("e")
	require.Equal(t, expLeafE, tree.Leaf(4))

	expLeafF := fnv32Hash("f")
	require.Equal(t, expLeafF, tree.Leaf(5))

	expLeafG := fnv32Hash("g")
	require.Equal(t, expLeafG, tree.Leaf(6))

	expLeafH := fnv32Hash("h")
	require.Equal(t, expLeafH, tree.Leaf(7))

	expLeafI := fnv32Hash("i")
	require.Equal(t, expLeafI, tree.Leaf(8))

	expLeafJ := fnv32Hash("j")
	require.Equal(t, expLeafJ, tree.Leaf(9))

	expLeafK := fnv32Hash("k")
	require.Equal(t, expLeafK, tree.Leaf(10))

	expLeafL := fnv32Hash("l")
	require.Equal(t, expLeafL, tree.Leaf(11))

	expLeafM := fnv32Hash("m")
	require.Equal(t, expLeafM, tree.Leaf(12))

	expLeafN := fnv32Hash("n")
	require.Equal(t, expLeafN, tree.Leaf(13))

	expLeafO := fnv32Hash("o")
	require.Equal(t, expLeafO, tree.Leaf(14))

	expLeafP := fnv32Hash("p")
	require.Equal(t, expLeafP, tree.Leaf(15))

	expLeafQ := fnv32Hash("q")
	require.Equal(t, expLeafQ, tree.Leaf(16))

	expLeafR := fnv32Hash("r")
	require.Equal(t, expLeafR, tree.Leaf(17))

	expLeafS := fnv32Hash("s")
	require.Equal(t, expLeafS, tree.Leaf(18))

	expLeafT := fnv32Hash("t")
	require.Equal(t, expLeafT, tree.Leaf(19))

	expLeafU := fnv32Hash("u")
	require.Equal(t, expLeafU, tree.Leaf(20))

	expNodeLM := fnv32Hash(string(expLeafL) + string(expLeafM))
	expNodeNO := fnv32Hash(string(expLeafN) + string(expLeafO))
	expNodePQ := fnv32Hash(string(expLeafP) + string(expLeafQ))
	expNodeRS := fnv32Hash(string(expLeafR) + string(expLeafS))
	expNodeTU := fnv32Hash(string(expLeafT) + string(expLeafU))

	expNodeAB := fnv32Hash(string(expLeafA) + string(expLeafB))
	expNodeCD := fnv32Hash(string(expLeafC) + string(expLeafD))
	expNodeEF := fnv32Hash(string(expLeafE) + string(expLeafF))
	expNodeGH := fnv32Hash(string(expLeafG) + string(expLeafH))
	expNodeIJ := fnv32Hash(string(expLeafI) + string(expLeafJ))

	expNodeKLM := fnv32Hash(string(expLeafK) + string(expNodeLM))
	expNodeNOPQ := fnv32Hash(string(expNodeNO) + string(expNodePQ))
	expNodeRSTU := fnv32Hash(string(expNodeRS) + string(expNodeTU))

	expNodeABCD := fnv32Hash(string(expNodeAB) + string(expNodeCD))
	expNodeEFGH := fnv32Hash(string(expNodeEF) + string(expNodeGH))
	expNodeIJKLM := fnv32Hash(string(expNodeIJ) + string(expNodeKLM))
	expNodeNOPQRSTU := fnv32Hash(string(expNodeNOPQ) + string(expNodeRSTU))

	expNodeABCDEFGH := fnv32Hash(string(expNodeABCD) + string(expNodeEFGH))
	expNodeIJKLMNOPQRSTU := fnv32Hash(string(expNodeIJKLM) + string(expNodeNOPQRSTU))

	expRoot := fnv32Hash(string(expNodeABCDEFGH) + string(expNodeIJKLMNOPQRSTU))

	t.Run("proof cutoff = 0", func(t *testing.T) {
		require.Equal(t, [][]byte{
			expRoot,
		}, res.RootProof)

		require.Equal(t, [][]byte{
			expLeafB,
			expNodeCD,
			expNodeEFGH,
			expNodeIJKLMNOPQRSTU,
		}, res.Proofs[0])

		require.Equal(t, [][]byte{
			expLeafA,
			expNodeCD,
			expNodeEFGH,
			expNodeIJKLMNOPQRSTU,
		}, res.Proofs[1])

		require.Equal(t, [][]byte{
			expLeafD,
			expNodeAB,
			expNodeEFGH,
			expNodeIJKLMNOPQRSTU,
		}, res.Proofs[2])

		require.Equal(t, [][]byte{
			expLeafC,
			expNodeAB,
			expNodeEFGH,
			expNodeIJKLMNOPQRSTU,
		}, res.Proofs[3])

		require.Equal(t, [][]byte{
			expLeafF,
			expNodeGH,
			expNodeABCD,
			expNodeIJKLMNOPQRSTU,
		}, res.Proofs[4])

		require.Equal(t, [][]byte{
			expLeafE,
			expNodeGH,
			expNodeABCD,
			expNodeIJKLMNOPQRSTU,
		}, res.Proofs[5])

		require.Equal(t, [][]byte{
			expLeafH,
			expNodeEF,
			expNodeABCD,
			expNodeIJKLMNOPQRSTU,
		}, res.Proofs[6])

		require.Equal(t, [][]byte{
			expLeafG,
			expNodeEF,
			expNodeABCD,
			expNodeIJKLMNOPQRSTU,
		}, res.Proofs[7])

		require.Equal(t, [][]byte{
			expLeafJ,
			expNodeKLM,
			expNodeNOPQRSTU,
			expNodeABCDEFGH,
		}, res.Proofs[8])

		require.Equal(t, [][]byte{
			expLeafI,
			expNodeKLM,
			expNodeNOPQRSTU,
			expNodeABCDEFGH,
		}, res.Proofs[9])

		require.Equal(t, [][]byte{
			expNodeLM,
			expNodeIJ,
			expNodeNOPQRSTU,
			expNodeABCDEFGH,
		}, res.Proofs[10])

		require.Equal(t, [][]byte{
			expLeafM,
			expLeafK,
			expNodeIJ,
			expNodeNOPQRSTU,
			expNodeABCDEFGH,
		}, res.Proofs[11])

		require.Equal(t, [][]byte{
			expLeafL,
			expLeafK,
			expNodeIJ,
			expNodeNOPQRSTU,
			expNodeABCDEFGH,
		}, res.Proofs[12])

		require.Equal(t, [][]byte{
			expLeafO,
			expNodePQ,
			expNodeRSTU,
			expNodeIJKLM,
			expNodeABCDEFGH,
		}, res.Proofs[13]) // N

		require.Equal(t, [][]byte{
			expLeafN,
			expNodePQ,
			expNodeRSTU,
			expNodeIJKLM,
			expNodeABCDEFGH,
		}, res.Proofs[14])

		require.Equal(t, [][]byte{
			expLeafQ,
			expNodeNO,
			expNodeRSTU,
			expNodeIJKLM,
			expNodeABCDEFGH,
		}, res.Proofs[15])

		require.Equal(t, [][]byte{
			expLeafP,
			expNodeNO,
			expNodeRSTU,
			expNodeIJKLM,
			expNodeABCDEFGH,
		}, res.Proofs[16])

		require.Equal(t, [][]byte{
			expLeafS,
			expNodeTU,
			expNodeNOPQ,
			expNodeIJKLM,
			expNodeABCDEFGH,
		}, res.Proofs[17])

		require.Equal(t, [][]byte{
			expLeafR,
			expNodeTU,
			expNodeNOPQ,
			expNodeIJKLM,
			expNodeABCDEFGH,
		}, res.Proofs[18])

		require.Equal(t, [][]byte{
			expLeafU,
			expNodeRS,
			expNodeNOPQ,
			expNodeIJKLM,
			expNodeABCDEFGH,
		}, res.Proofs[19])

		require.Equal(t, [][]byte{
			expLeafT,
			expNodeRS,
			expNodeNOPQ,
			expNodeIJKLM,
			expNodeABCDEFGH,
		}, res.Proofs[20])
	})
}

func TestTree_Populate_context_3_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(3, 32)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
	}

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: bcsha256.Hasher{},
		Nonce:  []byte("N."),
	})

	expLeaf0 := sha256Hash("N.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expNode12 := sha256Hash(
		"N.\x00\x01Hl." + expLeaf1 + "\x00\x02Hr." + expLeaf2,
	)

	expRoot := sha256Hash(
		"N.\x00\x00Hl." + expLeaf0 + "\x00\x02Hr." + expNode12,
	)
	require.Equal(t, expRoot, string(res.RootProof[0]))
}

func TestTree_Populate_context_4_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(4, 32)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	}

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: bcsha256.Hasher{},
		Nonce:  []byte("N."),
	})

	expLeaf0 := sha256Hash("N.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expLeaf3 := sha256Hash("N.\x00\x03L.three")
	require.Equal(t, expLeaf3, string(tree.Leaf(3)))

	expNode01 := sha256Hash(
		"N.\x00\x00Hl." + expLeaf0 + "\x00\x01Hr." + expLeaf1,
	)
	expNode23 := sha256Hash(
		"N.\x00\x02Hl." + expLeaf2 + "\x00\x03Hr." + expLeaf3,
	)

	expRoot := sha256Hash(
		"N.\x00\x00Hl." + expNode01 + "\x00\x03Hr." + expNode23,
	)
	require.Equal(t, expRoot, string(res.RootProof[0]))
}

func TestTree_Populate_context_6_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(6, 32)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
		[]byte("four"),
		[]byte("five"),
	}

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: bcsha256.Hasher{},
		Nonce:  []byte("N."),
	})

	expLeaf0 := sha256Hash("N.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expLeaf3 := sha256Hash("N.\x00\x03L.three")
	require.Equal(t, expLeaf3, string(tree.Leaf(3)))

	expLeaf4 := sha256Hash("N.\x00\x04L.four")
	require.Equal(t, expLeaf4, string(tree.Leaf(4)))

	expLeaf5 := sha256Hash("N.\x00\x05L.five")
	require.Equal(t, expLeaf5, string(tree.Leaf(5)))

	expNode01 := sha256Hash(
		"N.\x00\x00Hl." + expLeaf0 + "\x00\x01Hr." + expLeaf1,
	)
	expNode23 := sha256Hash(
		"N.\x00\x02Hl." + expLeaf2 + "\x00\x03Hr." + expLeaf3,
	)
	expNode45 := sha256Hash(
		"N.\x00\x04Hl." + expLeaf4 + "\x00\x05Hr." + expLeaf5,
	)
	expNode2345 := sha256Hash(
		"N.\x00\x02Hl." + expNode23 + "\x00\x05Hr." + expNode45,
	)

	expRoot := sha256Hash(
		"N.\x00\x00Hl." + expNode01 + "\x00\x05Hr." + expNode2345,
	)
	require.Equal(t, expRoot, string(res.RootProof[0]))
}

func TestTree_Populate_context_8_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(8, 32)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
		[]byte("four"),
		[]byte("five"),
		[]byte("six"),
		[]byte("seven"),
	}

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: bcsha256.Hasher{},
		Nonce:  []byte("N."),
	})

	expLeaf0 := sha256Hash("N.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expLeaf3 := sha256Hash("N.\x00\x03L.three")
	require.Equal(t, expLeaf3, string(tree.Leaf(3)))

	expLeaf4 := sha256Hash("N.\x00\x04L.four")
	require.Equal(t, expLeaf4, string(tree.Leaf(4)))

	expLeaf5 := sha256Hash("N.\x00\x05L.five")
	require.Equal(t, expLeaf5, string(tree.Leaf(5)))

	expLeaf6 := sha256Hash("N.\x00\x06L.six")
	require.Equal(t, expLeaf6, string(tree.Leaf(6)))

	expLeaf7 := sha256Hash("N.\x00\x07L.seven")
	require.Equal(t, expLeaf7, string(tree.Leaf(7)))

	expNode01 := sha256Hash(
		"N.\x00\x00Hl." + expLeaf0 + "\x00\x01Hr." + expLeaf1,
	)
	expNode23 := sha256Hash(
		"N.\x00\x02Hl." + expLeaf2 + "\x00\x03Hr." + expLeaf3,
	)
	expNode0123 := sha256Hash(
		"N.\x00\x00Hl." + expNode01 + "\x00\x03Hr." + expNode23,
	)

	expNode45 := sha256Hash(
		"N.\x00\x04Hl." + expLeaf4 + "\x00\x05Hr." + expLeaf5,
	)
	expNode67 := sha256Hash(
		"N.\x00\x06Hl." + expLeaf6 + "\x00\x07Hr." + expLeaf7,
	)
	expNode4567 := sha256Hash(
		"N.\x00\x04Hl." + expNode45 + "\x00\x07Hr." + expNode67,
	)

	expRoot := sha256Hash(
		"N.\x00\x00Hl." + expNode0123 + "\x00\x07Hr." + expNode4567,
	)
	require.Equal(t, expRoot, string(res.RootProof[0]))
}

func TestTree_proofDetail_2(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(2, 32)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
	}

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: bcsha256.Hasher{},
		Nonce:  []byte("N."),
	})

	expLeaf0 := sha256Hash("N.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expRoot := sha256Hash(
		"N.\x00\x00Hl." + expLeaf0 + "\x00\x01Hr." + expLeaf1,
	)

	require.Equal(t, [][]byte{
		[]byte(expRoot),
	}, res.RootProof)

	require.Equal(t, [][]byte{
		[]byte(expLeaf1),
	}, res.Proofs[0])

	require.Equal(t, [][]byte{
		[]byte(expLeaf0),
	}, res.Proofs[1])
}

func TestTree_proofDetail_3(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(3, 32)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
	}

	/* Tree structure:

	012
	0 12
	x 1 2

	*/

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: bcsha256.Hasher{},
		Nonce:  []byte("N."),
	})

	expLeaf0 := sha256Hash("N.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expNode12 := sha256Hash(
		"N.\x00\x01Hl." + expLeaf1 + "\x00\x02Hr." + expLeaf2,
	)

	expRoot := sha256Hash(
		"N.\x00\x00Hl." + expLeaf0 + "\x00\x02Hr." + expNode12,
	)
	require.Equal(t, expRoot, string(res.RootProof[0]))

	require.Equal(t, [][]byte{
		[]byte(expRoot),
	}, res.RootProof)

	require.Equal(t, [][]byte{
		[]byte(expNode12),
	}, res.Proofs[0])

	require.Equal(t, [][]byte{
		[]byte(expLeaf2),
		[]byte(expLeaf0),
	}, res.Proofs[1])

	require.Equal(t, [][]byte{
		[]byte(expLeaf1),
		[]byte(expLeaf0),
	}, res.Proofs[2])
}

func TestTree_proofDetail_4(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(4, 32)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	}

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: bcsha256.Hasher{},
		Nonce:  []byte("N."),
	})

	expLeaf0 := sha256Hash("N.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expLeaf3 := sha256Hash("N.\x00\x03L.three")
	require.Equal(t, expLeaf3, string(tree.Leaf(3)))

	expNode01 := sha256Hash(
		"N.\x00\x00Hl." + expLeaf0 + "\x00\x01Hr." + expLeaf1,
	)
	expNode23 := sha256Hash(
		"N.\x00\x02Hl." + expLeaf2 + "\x00\x03Hr." + expLeaf3,
	)

	expRoot := sha256Hash(
		"N.\x00\x00Hl." + expNode01 + "\x00\x03Hr." + expNode23,
	)

	require.Equal(t, [][]byte{
		[]byte(expRoot),
	}, res.RootProof)

	require.Equal(t, [][]byte{
		[]byte(expLeaf1),
		[]byte(expNode23),
	}, res.Proofs[0])

	require.Equal(t, [][]byte{
		[]byte(expLeaf0),
		[]byte(expNode23),
	}, res.Proofs[1])

	require.Equal(t, [][]byte{
		[]byte(expLeaf3),
		[]byte(expNode01),
	}, res.Proofs[2])

	require.Equal(t, [][]byte{
		[]byte(expLeaf2),
		[]byte(expNode01),
	}, res.Proofs[3])
}

func TestTree_proofDetail_6(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(6, 32)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
		[]byte("four"),
		[]byte("five"),
	}

	/* Tree structure:

	012345
	01 2345
	0 1 23 45
	x x x x 2 3 4 5

	*/

	res := tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: bcsha256.Hasher{},
		Nonce:  []byte("N."),
	})

	expLeaf0 := sha256Hash("N.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expLeaf3 := sha256Hash("N.\x00\x03L.three")
	require.Equal(t, expLeaf3, string(tree.Leaf(3)))

	expLeaf4 := sha256Hash("N.\x00\x04L.four")
	require.Equal(t, expLeaf4, string(tree.Leaf(4)))

	expLeaf5 := sha256Hash("N.\x00\x05L.five")
	require.Equal(t, expLeaf5, string(tree.Leaf(5)))

	expNode01 := sha256Hash(
		"N.\x00\x00Hl." + expLeaf0 + "\x00\x01Hr." + expLeaf1,
	)
	expNode23 := sha256Hash(
		"N.\x00\x02Hl." + expLeaf2 + "\x00\x03Hr." + expLeaf3,
	)
	expNode45 := sha256Hash(
		"N.\x00\x04Hl." + expLeaf4 + "\x00\x05Hr." + expLeaf5,
	)
	expNode2345 := sha256Hash(
		"N.\x00\x02Hl." + expNode23 + "\x00\x05Hr." + expNode45,
	)

	expRoot := sha256Hash(
		"N.\x00\x00Hl." + expNode01 + "\x00\x05Hr." + expNode2345,
	)

	require.Equal(t, [][]byte{
		[]byte(expRoot),
	}, res.RootProof)

	require.Equal(t, [][]byte{
		[]byte(expLeaf1),
		[]byte(expNode2345),
	}, res.Proofs[0])

	require.Equal(t, [][]byte{
		[]byte(expLeaf0),
		[]byte(expNode2345),
	}, res.Proofs[1])

	require.Equal(t, [][]byte{
		[]byte(expLeaf3),
		[]byte(expNode45),
		[]byte(expNode01),
	}, res.Proofs[2])

	require.Equal(t, [][]byte{
		[]byte(expLeaf2),
		[]byte(expNode45),
		[]byte(expNode01),
	}, res.Proofs[3])

	require.Equal(t, [][]byte{
		[]byte(expLeaf5),
		[]byte(expNode23),
		[]byte(expNode01),
	}, res.Proofs[4])

	require.Equal(t, [][]byte{
		[]byte(expLeaf4),
		[]byte(expNode23),
		[]byte(expNode01),
	}, res.Proofs[5])
}

// fnv32Hash is a convenience function to hash a string.
func fnv32Hash(in string) []byte {
	h := fnv.New32()
	_, _ = h.Write([]byte(in))
	return h.Sum(nil)
}

// fnv32Hasher is a simple, test-only hasher implementation.
// It is not suitable for production because it uses a non-cryptographic hash
// and it does not include prefixes necessary for preimage attack avoidance.
// But, this simplicity does keep test assertions easier to follow.
type fnv32Hasher struct {
	IncludeNonce bool
}

func (f fnv32Hasher) Leaf(in []byte, c bcmerkle.LeafContext, dst []byte) {
	h := fnv.New32()
	if f.IncludeNonce {
		_, _ = h.Write(c.Nonce)
	}
	_, _ = h.Write(in)
	h.Sum(dst)
}

func (f fnv32Hasher) Node(left, right []byte, c bcmerkle.NodeContext, dst []byte) {
	h := fnv.New32()
	if f.IncludeNonce {
		_, _ = h.Write(c.Nonce)
	}
	_, _ = h.Write(left)
	_, _ = h.Write(right)
	h.Sum(dst)
}

func sha256Hash(in string) string {
	res := sha256.Sum256([]byte(in))
	return string(res[:])
}
