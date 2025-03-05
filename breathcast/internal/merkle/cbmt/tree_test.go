package cbmt_test

import (
	"crypto/sha256"
	"hash/fnv"
	"io"
	"testing"

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

	tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher: fnv32Hasher{},
	})

	expLeaf0 := fnv32Hash("hello")
	require.Equal(t, expLeaf0, tree.Leaf(0))

	expLeaf1 := fnv32Hash("world")
	require.Equal(t, expLeaf1, tree.Leaf(1))

	expRoot := fnv32Hash(string(expLeaf0) + string(expLeaf1))
	require.Equal(t, expRoot, tree.Root())
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

	tree.Populate(leaves, cbmt.PopulateConfig{
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
	require.Equal(t, expRoot, tree.Root())
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

	tree.Populate(leaves, cbmt.PopulateConfig{
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
	require.Equal(t, expRoot, tree.Root())
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

	tree.Populate(leaves, cbmt.PopulateConfig{
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

	require.Equal(t, expRoot, tree.Root())
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

	tree.Populate(leaves, cbmt.PopulateConfig{
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
	require.Equal(t, expRoot, tree.Root())
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

	tree.Populate(leaves, cbmt.PopulateConfig{
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
	require.Equal(t, expRoot, tree.Root())
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

	tree.Populate(leaves, cbmt.PopulateConfig{
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

	expLeaf7 := fnv32Hash("seven")
	require.Equal(t, expLeaf7, tree.Leaf(7))

	expNode01 := fnv32Hash(string(expLeaf0) + string(expLeaf1))
	expNode23 := fnv32Hash(string(expLeaf2) + string(expLeaf3))
	expNode0123 := fnv32Hash(string(expNode01) + string(expNode23))

	expNode45 := fnv32Hash(string(expLeaf4) + string(expLeaf5))
	expNode67 := fnv32Hash(string(expLeaf6) + string(expLeaf7))
	expNode4567 := fnv32Hash(string(expNode45) + string(expNode67))

	expRoot := fnv32Hash(string(expNode0123) + string(expNode4567))
	require.Equal(t, expRoot, tree.Root())
}

func TestTree_Populate_context_3_leaves(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(3, 32)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
	}

	tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher:    sha256Hasher{},
		Nonce:     []byte("N."),
		BlockHash: []byte("BH."),
	})

	expLeaf0 := sha256Hash("N.BH.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.BH.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.BH.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expNode12 := sha256Hash(
		"N.BH.\x00\x01Hl." + expLeaf1 + "\x00\x02Hr." + expLeaf2,
	)

	expRoot := sha256Hash(
		"N.BH.\x00\x00Hl." + expLeaf0 + "\x00\x02Hr." + expNode12,
	)
	require.Equal(t, expRoot, string(tree.Root()))
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

	tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher:    sha256Hasher{},
		Nonce:     []byte("N."),
		BlockHash: []byte("BH."),
	})

	expLeaf0 := sha256Hash("N.BH.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.BH.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.BH.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expLeaf3 := sha256Hash("N.BH.\x00\x03L.three")
	require.Equal(t, expLeaf3, string(tree.Leaf(3)))

	expNode01 := sha256Hash(
		"N.BH.\x00\x00Hl." + expLeaf0 + "\x00\x01Hr." + expLeaf1,
	)
	expNode23 := sha256Hash(
		"N.BH.\x00\x02Hl." + expLeaf2 + "\x00\x03Hr." + expLeaf3,
	)

	expRoot := sha256Hash(
		"N.BH.\x00\x00Hl." + expNode01 + "\x00\x03Hr." + expNode23,
	)
	require.Equal(t, expRoot, string(tree.Root()))
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

	tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher:    sha256Hasher{},
		Nonce:     []byte("N."),
		BlockHash: []byte("BH."),
	})

	expLeaf0 := sha256Hash("N.BH.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.BH.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.BH.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expLeaf3 := sha256Hash("N.BH.\x00\x03L.three")
	require.Equal(t, expLeaf3, string(tree.Leaf(3)))

	expLeaf4 := sha256Hash("N.BH.\x00\x04L.four")
	require.Equal(t, expLeaf4, string(tree.Leaf(4)))

	expLeaf5 := sha256Hash("N.BH.\x00\x05L.five")
	require.Equal(t, expLeaf5, string(tree.Leaf(5)))

	expNode01 := sha256Hash(
		"N.BH.\x00\x00Hl." + expLeaf0 + "\x00\x01Hr." + expLeaf1,
	)
	expNode23 := sha256Hash(
		"N.BH.\x00\x02Hl." + expLeaf2 + "\x00\x03Hr." + expLeaf3,
	)
	expNode45 := sha256Hash(
		"N.BH.\x00\x04Hl." + expLeaf4 + "\x00\x05Hr." + expLeaf5,
	)
	expNode2345 := sha256Hash(
		"N.BH.\x00\x02Hl." + expNode23 + "\x00\x05Hr." + expNode45,
	)

	expRoot := sha256Hash(
		"N.BH.\x00\x00Hl." + expNode01 + "\x00\x05Hr." + expNode2345,
	)
	require.Equal(t, expRoot, string(tree.Root()))
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

	tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher:    sha256Hasher{},
		Nonce:     []byte("N."),
		BlockHash: []byte("BH."),
	})

	expLeaf0 := sha256Hash("N.BH.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.BH.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.BH.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expLeaf3 := sha256Hash("N.BH.\x00\x03L.three")
	require.Equal(t, expLeaf3, string(tree.Leaf(3)))

	expLeaf4 := sha256Hash("N.BH.\x00\x04L.four")
	require.Equal(t, expLeaf4, string(tree.Leaf(4)))

	expLeaf5 := sha256Hash("N.BH.\x00\x05L.five")
	require.Equal(t, expLeaf5, string(tree.Leaf(5)))

	expLeaf6 := sha256Hash("N.BH.\x00\x06L.six")
	require.Equal(t, expLeaf6, string(tree.Leaf(6)))

	expLeaf7 := sha256Hash("N.BH.\x00\x07L.seven")
	require.Equal(t, expLeaf7, string(tree.Leaf(7)))

	expNode01 := sha256Hash(
		"N.BH.\x00\x00Hl." + expLeaf0 + "\x00\x01Hr." + expLeaf1,
	)
	expNode23 := sha256Hash(
		"N.BH.\x00\x02Hl." + expLeaf2 + "\x00\x03Hr." + expLeaf3,
	)
	expNode0123 := sha256Hash(
		"N.BH.\x00\x00Hl." + expNode01 + "\x00\x03Hr." + expNode23,
	)

	expNode45 := sha256Hash(
		"N.BH.\x00\x04Hl." + expLeaf4 + "\x00\x05Hr." + expLeaf5,
	)
	expNode67 := sha256Hash(
		"N.BH.\x00\x06Hl." + expLeaf6 + "\x00\x07Hr." + expLeaf7,
	)
	expNode4567 := sha256Hash(
		"N.BH.\x00\x04Hl." + expNode45 + "\x00\x07Hr." + expNode67,
	)

	expRoot := sha256Hash(
		"N.BH.\x00\x00Hl." + expNode0123 + "\x00\x07Hr." + expNode4567,
	)
	require.Equal(t, expRoot, string(tree.Root()))
}

func TestTree_GenerateProof_2(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(2, 32)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
	}

	tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher:    sha256Hasher{},
		Nonce:     []byte("N."),
		BlockHash: []byte("BH."),
	})

	expLeaf0 := sha256Hash("N.BH.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.BH.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	proof0 := tree.GenerateProof(0, nil)
	require.Equal(t, [][]byte{[]byte(expLeaf1)}, proof0)

	proof1 := tree.GenerateProof(1, nil)
	require.Equal(t, [][]byte{[]byte(expLeaf0)}, proof1)
}

func TestTree_GenerateProof_3(t *testing.T) {
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

	tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher:    sha256Hasher{},
		Nonce:     []byte("N."),
		BlockHash: []byte("BH."),
	})

	expLeaf0 := sha256Hash("N.BH.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.BH.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.BH.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expNode12 := sha256Hash(
		"N.BH.\x00\x01Hl." + expLeaf1 + "\x00\x02Hr." + expLeaf2,
	)

	expRoot := sha256Hash(
		"N.BH.\x00\x00Hl." + expLeaf0 + "\x00\x02Hr." + expNode12,
	)
	require.Equal(t, expRoot, string(tree.Root()))

	proof0 := tree.GenerateProof(0, nil)
	require.Equal(t, [][]byte{[]byte(expNode12)}, proof0)

	proof1 := tree.GenerateProof(1, nil)
	require.Equal(t, [][]byte{[]byte(expLeaf2), []byte(expLeaf0)}, proof1)

	proof2 := tree.GenerateProof(2, nil)
	require.Equal(t, [][]byte{[]byte(expLeaf1), []byte(expLeaf0)}, proof2)
}

func TestTree_GenerateProof_4(t *testing.T) {
	t.Parallel()

	tree := cbmt.NewEmptyTree(4, 32)

	leaves := [][]byte{
		[]byte("zero"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	}

	tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher:    sha256Hasher{},
		Nonce:     []byte("N."),
		BlockHash: []byte("BH."),
	})

	expLeaf0 := sha256Hash("N.BH.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.BH.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.BH.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expLeaf3 := sha256Hash("N.BH.\x00\x03L.three")
	require.Equal(t, expLeaf3, string(tree.Leaf(3)))

	expNode01 := sha256Hash(
		"N.BH.\x00\x00Hl." + expLeaf0 + "\x00\x01Hr." + expLeaf1,
	)
	expNode23 := sha256Hash(
		"N.BH.\x00\x02Hl." + expLeaf2 + "\x00\x03Hr." + expLeaf3,
	)

	proof0 := tree.GenerateProof(0, nil)
	require.Equal(t, [][]byte{
		[]byte(expLeaf1), []byte(expNode23),
	}, proof0)

	proof1 := tree.GenerateProof(1, nil)
	require.Equal(t, [][]byte{
		[]byte(expLeaf0), []byte(expNode23),
	}, proof1)

	proof2 := tree.GenerateProof(2, nil)
	require.Equal(t, [][]byte{
		[]byte(expLeaf3), []byte(expNode01),
	}, proof2)

	proof3 := tree.GenerateProof(3, nil)
	require.Equal(t, [][]byte{
		[]byte(expLeaf2), []byte(expNode01),
	}, proof3)
}

func TestTree_GenerateProof_6_leaves(t *testing.T) {
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

	tree.Populate(leaves, cbmt.PopulateConfig{
		Hasher:    sha256Hasher{},
		Nonce:     []byte("N."),
		BlockHash: []byte("BH."),
	})

	expLeaf0 := sha256Hash("N.BH.\x00\x00L.zero")
	require.Equal(t, expLeaf0, string(tree.Leaf(0)))

	expLeaf1 := sha256Hash("N.BH.\x00\x01L.one")
	require.Equal(t, expLeaf1, string(tree.Leaf(1)))

	expLeaf2 := sha256Hash("N.BH.\x00\x02L.two")
	require.Equal(t, expLeaf2, string(tree.Leaf(2)))

	expLeaf3 := sha256Hash("N.BH.\x00\x03L.three")
	require.Equal(t, expLeaf3, string(tree.Leaf(3)))

	expLeaf4 := sha256Hash("N.BH.\x00\x04L.four")
	require.Equal(t, expLeaf4, string(tree.Leaf(4)))

	expLeaf5 := sha256Hash("N.BH.\x00\x05L.five")
	require.Equal(t, expLeaf5, string(tree.Leaf(5)))

	expNode01 := sha256Hash(
		"N.BH.\x00\x00Hl." + expLeaf0 + "\x00\x01Hr." + expLeaf1,
	)
	expNode23 := sha256Hash(
		"N.BH.\x00\x02Hl." + expLeaf2 + "\x00\x03Hr." + expLeaf3,
	)
	expNode45 := sha256Hash(
		"N.BH.\x00\x04Hl." + expLeaf4 + "\x00\x05Hr." + expLeaf5,
	)
	expNode2345 := sha256Hash(
		"N.BH.\x00\x02Hl." + expNode23 + "\x00\x05Hr." + expNode45,
	)

	proof0 := tree.GenerateProof(0, nil)
	require.Equal(t, [][]byte{
		[]byte(expLeaf1), []byte(expNode2345),
	}, proof0)

	proof1 := tree.GenerateProof(1, nil)
	require.Equal(t, [][]byte{
		[]byte(expLeaf0), []byte(expNode2345),
	}, proof1)

	proof2 := tree.GenerateProof(2, nil)
	require.Equal(t, [][]byte{
		[]byte(expLeaf3), []byte(expNode45), []byte(expNode01),
	}, proof2)

	proof3 := tree.GenerateProof(3, nil)
	require.Equal(t, [][]byte{
		[]byte(expLeaf2), []byte(expNode45), []byte(expNode01),
	}, proof3)

	proof4 := tree.GenerateProof(4, nil)
	require.Equal(t, [][]byte{
		[]byte(expLeaf5), []byte(expNode23), []byte(expNode01),
	}, proof4)

	proof5 := tree.GenerateProof(5, nil)
	require.Equal(t, [][]byte{
		[]byte(expLeaf4), []byte(expNode23), []byte(expNode01),
	}, proof5)
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
	IncludeNonce, IncludeBlockHash bool
}

func (f fnv32Hasher) Leaf(in []byte, c cbmt.LeafContext, dst []byte) {
	h := fnv.New32()
	if f.IncludeNonce {
		_, _ = h.Write(c.Nonce)
	}
	if f.IncludeBlockHash {
		_, _ = h.Write(c.BlockHash)
	}
	_, _ = h.Write(in)
	h.Sum(dst)
}

func (f fnv32Hasher) Node(left, right []byte, n cbmt.NodeContext, dst []byte) {
	h := fnv.New32()
	if f.IncludeNonce {
		_, _ = h.Write(n.Nonce)
	}
	if f.IncludeBlockHash {
		_, _ = h.Write(n.BlockHash)
	}
	_, _ = h.Write(left)
	_, _ = h.Write(right)
	h.Sum(dst)
}

type sha256Hasher struct{}

func (s sha256Hasher) Leaf(in []byte, c cbmt.LeafContext, dst []byte) {
	h := sha256.New()
	_, _ = h.Write(c.Nonce)
	_, _ = h.Write(c.BlockHash)
	_, _ = h.Write(c.LeafIndex[:])
	_, _ = io.WriteString(h, "L.")
	_, _ = h.Write(in)
	h.Sum(dst)
}

func (s sha256Hasher) Node(left, right []byte, c cbmt.NodeContext, dst []byte) {
	if c.FirstLeafIndex == [2]byte{0, 0} && c.LastLeafIndex == [2]byte{0, 0} {
		panic("missed node context")
	}
	h := sha256.New()
	_, _ = h.Write(c.Nonce)
	_, _ = h.Write(c.BlockHash)
	_, _ = h.Write(c.FirstLeafIndex[:])
	_, _ = io.WriteString(h, "Hl.")
	_, _ = h.Write(left)
	_, _ = h.Write(c.LastLeafIndex[:])
	_, _ = io.WriteString(h, "Hr.")
	_, _ = h.Write(right)
	h.Sum(dst)
}

func sha256Hash(in string) string {
	res := sha256.Sum256([]byte(in))
	return string(res[:])
}
