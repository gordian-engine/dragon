package cbmt_test

import (
	"fmt"
	"math/bits"
	"math/rand/v2"
	"testing"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

// This test implicitly covers that a variety of leaf counts
// and cutoff tiers do not panic.
//
// Other tests assert behavior of other methods.
func TestNewPartialTree(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData

	for nl := uint16(2); nl < 18; nl++ {
		for c := uint8(0); c < 3; c++ {
			t.Run(fmt.Sprintf("nLeaves = %d, cutoff tier = %d", nl, c), func(t *testing.T) {
				t.Parallel()

				fullTree := cbmt.NewEmptyTree(nl, bcsha256.HashSize)

				nonce := []byte(t.Name())

				res := fullTree.Populate(leafData[:nl], cbmt.PopulateConfig{
					Hasher:          bcsha256.Hasher{},
					Nonce:           nonce,
					ProofCutoffTier: c,
				})

				pt := cbmt.NewPartialTree(cbmt.PartialTreeConfig{
					NLeaves: nl,

					Hasher:   bcsha256.Hasher{},
					HashSize: bcsha256.HashSize,

					Nonce: nonce,

					ProofCutoffTier: c,

					RootProofs: res.RootProof,
				})
				require.NotNil(t, pt)
			})
		}
	}
}

func TestPartialTree_Clone_concurrency(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:4]
	pt, res := NewTestPartialTree(t, leafData, 0)

	ready := make(chan struct{}, 4)
	startAll := make(chan struct{})
	done := make(chan *cbmt.PartialTree)

	for i := range 4 {
		c := pt.Clone()
		go func() {
			dtest.SendSoon(t, ready, struct{}{})
			_ = dtest.ReceiveSoon(t, startAll)
			require.NoError(t, c.AddLeaf(uint16(i), leafData[i], res.Proofs[i]))
			require.True(t, c.HasLeaf(uint16(i)))

			dtest.SendSoon(t, done, c)
		}()
	}
	for range 4 {
		_ = dtest.ReceiveSoon(t, ready)
	}

	close(startAll)

	for range 4 {
		c := dtest.ReceiveSoon(t, done)

		pt.MergeFrom(c)
	}
}

func TestPartialTree_Clone_serialReset(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:4]
	pt, res := NewTestPartialTree(t, leafData, 0)

	c := pt.Clone()
	require.NoError(t, c.AddLeaf(3, leafData[3], res.Proofs[3]))
	pt.MergeFrom(c)

	for i := range uint16(3) {
		pt.ResetClone(c)

		require.NoError(t, c.AddLeaf(i, leafData[i], res.Proofs[i]))

		pt.MergeFrom(c)
	}

	for i := range uint16(4) {
		require.True(t, pt.HasLeaf(i))
	}
}

func TestPartialTree_AddLeaf_4_2(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:4]

	/* Tree layout:

	0123
	01 23
	0 1 2 3
	*/

	pt, res := NewTestPartialTree(t, leafData, 2)

	// When the cutoff tier covers the entire tree,
	// we still can add the leaf without error the first time:
	require.NoError(t, pt.AddLeaf(0, leafData[0], res.Proofs[0]))

	// But adding it a second time results in ErrAlreadyHadProof.
	require.ErrorIs(t, cbmt.ErrAlreadyHadProof, pt.AddLeaf(0, leafData[0], res.Proofs[0]))

	// And trying to add the wrong leaf data returns the appropriate error.
	require.ErrorIs(t, cbmt.ErrIncorrectLeafData, pt.AddLeaf(0, []byte("wrong"), res.Proofs[0]))
}

func TestPartialTree_AddLeaf_5_2(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:5]

	/* Tree layout:

	01234
	01 234
	0 1 2 34
	x x x x x x 3 4
	*/

	pt, res := NewTestPartialTree(t, leafData, 2)

	// Root proofs cover everything but spillover leaves.
	require.Len(t, res.Proofs[4], 1)

	// Successful add the first time, then error the next time.
	require.NoError(t, pt.AddLeaf(4, leafData[4], res.Proofs[4]))
	require.ErrorIs(t, cbmt.ErrAlreadyHadProof, pt.AddLeaf(4, leafData[4], res.Proofs[4]))

	// And trying to add the wrong leaf data returns the appropriate error.
	require.ErrorIs(t, cbmt.ErrIncorrectLeafData, pt.AddLeaf(4, []byte("wrong"), res.Proofs[4]))
}

func TestPartialTree_AddLeaf_5_3(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:5]

	/* Tree layout:

	01234
	01 234
	0 1 2 34
	x x x x x x 3 4
	*/

	pt, res := NewTestPartialTree(t, leafData, 3)

	// Successful add the first time, then error the next time.
	require.NoError(t, pt.AddLeaf(4, leafData[4], res.Proofs[4]))
	require.ErrorIs(t, cbmt.ErrAlreadyHadProof, pt.AddLeaf(4, leafData[4], res.Proofs[4]))

	// And trying to add the wrong leaf data returns the appropriate error.
	require.ErrorIs(t, cbmt.ErrIncorrectLeafData, pt.AddLeaf(4, []byte("wrong"), res.Proofs[4]))
}

func TestPartialTree_AddLeaf_4_1(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:4]

	/* Tree layout:

	0123
	01 23
	0 1 2 3
	*/

	pt, res := NewTestPartialTree(t, leafData, 1)

	// First add is no error.
	require.NoError(t, pt.AddLeaf(0, leafData[0], res.Proofs[0]))
	require.ErrorIs(t, cbmt.ErrAlreadyHadProof, pt.AddLeaf(0, leafData[0], res.Proofs[0]))

	// And trying to add the wrong leaf data returns the appropriate error.
	require.ErrorIs(t, cbmt.ErrIncorrectLeafData, pt.AddLeaf(0, []byte("wrong"), res.Proofs[0]))

	// Also add another leaf that is on the right half of the leaves.
	require.NoError(t, pt.AddLeaf(2, leafData[2], res.Proofs[2]))
	require.ErrorIs(t, cbmt.ErrAlreadyHadProof, pt.AddLeaf(2, leafData[2], res.Proofs[2]))
}

func TestPartialTree_AddLeaf_6_1(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:6]

	/* Tree layout:

	0123456
	01 2345
	0 1 23 45
	x x x x 2 3 4 5
	*/

	pt, res := NewTestPartialTree(t, leafData, 1)

	// First add is no error.
	require.NoError(t, pt.AddLeaf(1, leafData[1], res.Proofs[1]))
	require.ErrorIs(t, cbmt.ErrAlreadyHadProof, pt.AddLeaf(1, leafData[1], res.Proofs[1]))

	// And trying to add the wrong leaf data returns the appropriate error.
	require.ErrorIs(t, cbmt.ErrIncorrectLeafData, pt.AddLeaf(1, []byte("wrong"), res.Proofs[1]))
}

func TestPartialTree_AddLeaf_7_0(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:7]

	/* Tree layout:

	0123456
	012 3456
	0 12 34 56
	x x 1 2 3 4 5 6
	*/

	pt, res := NewTestPartialTree(t, leafData, 0)

	// First add is no error.
	require.NoError(t, pt.AddLeaf(0, leafData[0], res.Proofs[0]))
	require.ErrorIs(t, cbmt.ErrAlreadyHadProof, pt.AddLeaf(0, leafData[0], res.Proofs[0]))

	// And trying to add the wrong leaf data returns the appropriate error.
	require.ErrorIs(t, cbmt.ErrIncorrectLeafData, pt.AddLeaf(0, []byte("wrong"), res.Proofs[0]))
}

func TestPartialTree_AddLeaf_9_2(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:9]

	/* Tree layout:

	0123456789ab
	0123 456789ab
	01 23 456 789a
	0 1 2 3 4 5 6 78
	x x x x x x x x x x x x x x 7 8

	*/

	pt, res := NewTestPartialTree(t, leafData, 2)

	// First add is no error.
	require.NoError(t, pt.AddLeaf(6, leafData[6], res.Proofs[6]))
	require.ErrorIs(t, cbmt.ErrAlreadyHadProof, pt.AddLeaf(6, leafData[6], res.Proofs[6]))

	// And trying to add the wrong leaf data returns the appropriate error.
	require.ErrorIs(t, cbmt.ErrIncorrectLeafData, pt.AddLeaf(6, []byte("wrong"), res.Proofs[6]))
}

func TestPartialTree_AddLeaf_11_1(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:11]

	/* Tree layout:

	0123456789ab
	0123 456789ab
	01 23 456 789a
	0 1 2 3 4 56 78 9a
	x x x x x x x x x 4 5 6 7 8 9 a
	*/

	pt, res := NewTestPartialTree(t, leafData, 1)

	// First add is no error.
	require.NoError(t, pt.AddLeaf(3, leafData[3], res.Proofs[3]))
	require.ErrorIs(t, cbmt.ErrAlreadyHadProof, pt.AddLeaf(3, leafData[3], res.Proofs[3]))

	// And trying to add the wrong leaf data returns the appropriate error.
	require.ErrorIs(t, cbmt.ErrIncorrectLeafData, pt.AddLeaf(3, []byte("wrong"), res.Proofs[3]))
}

func TestPartialTree_AddLeaf_11_2(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:11]

	/* Tree layout:

	0123456789ab
	0123 456789ab
	01 23 456 789a
	0 1 2 3 4 56 78 9a
	x x x x x x x x x 4 5 6 7 8 9 a
	*/

	pt, res := NewTestPartialTree(t, leafData, 2)

	// First add is no error.
	require.NoError(t, pt.AddLeaf(0, leafData[0], res.Proofs[0]))
	require.ErrorIs(t, cbmt.ErrAlreadyHadProof, pt.AddLeaf(0, leafData[0], res.Proofs[0]))

	// And trying to add the wrong leaf data returns the appropriate error.
	require.ErrorIs(t, cbmt.ErrIncorrectLeafData, pt.AddLeaf(0, []byte("wrong"), res.Proofs[0]))
}

func TestPartialTree_AddLeaf_15_0(t *testing.T) {
	t.Parallel()

	leafData := fixtureLeafData[:15]

	/* Tree layout:

	0123456789abcde
	0123456 789abcde
	012 3456 789a bcde
	0 12 34 56 78 9a bc de
	x 1 2 3 4 5 6 7 8 9 a b c d e
	*/

	pt, res := NewTestPartialTree(t, leafData, 0)

	// First add is no error.
	require.NoError(t, pt.AddLeaf(10, leafData[10], res.Proofs[10]))
	require.ErrorIs(t, cbmt.ErrAlreadyHadProof, pt.AddLeaf(10, leafData[10], res.Proofs[10]))

	// And trying to add the wrong leaf data returns the appropriate error.
	require.ErrorIs(t, cbmt.ErrIncorrectLeafData, pt.AddLeaf(10, []byte("wrong"), res.Proofs[10]))
}

func TestPartialTree_AddLeaf_sequence(t *testing.T) {
	t.Parallel()
	for nl := uint16(3); nl < 18; nl++ {
		depth := uint8(bits.Len16(nl))
		for c := uint8(0); c <= depth; c++ {
			name := fmt.Sprintf("nLeaves=%d, cutoff=%d", nl, c)
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				leafData := fixtureLeafData[:nl]

				pt, res := NewTestPartialTree(t, leafData, c)

				// Use a fixed seed per test,
				// so we can add leaves in a determinstic pseudorandom order.
				var seed [32]byte
				copy(seed[:], t.Name())
				rng := rand.New(rand.NewChaCha8(seed))

				leafIdxs := make([]uint16, nl)
				for i := range nl {
					leafIdxs[i] = i
				}
				rng.Shuffle(len(leafIdxs), func(i, j int) {
					leafIdxs[i], leafIdxs[j] = leafIdxs[j], leafIdxs[i]
				})

				for _, li := range leafIdxs {
					require.NoError(t, pt.AddLeaf(li, leafData[li], res.Proofs[li]))
				}
			})
		}
	}
}

func TestPartialTree_Complete_4_1(t *testing.T) {
	t.Parallel()
	leafData := fixtureLeafData[:4]
	pt, res := NewTestPartialTree(t, leafData, 0)

	for i := range uint16(3) {
		require.NoError(t, pt.AddLeaf(i, leafData[i], res.Proofs[i]))
	}

	c := pt.Complete([][]byte{
		leafData[3],
	})

	require.Equal(t, c.Proofs, [][][]byte{
		res.Proofs[3],
	})
}

func NewTestPartialTree(t *testing.T, leafData [][]byte, cutoffTier uint8) (*cbmt.PartialTree, cbmt.PopulateResult) {
	t.Helper()

	fullTree := cbmt.NewEmptyTree(uint16(len(leafData)), bcsha256.HashSize)

	nonce := []byte(t.Name())

	res := fullTree.Populate(leafData, cbmt.PopulateConfig{
		Hasher:          bcsha256.Hasher{},
		Nonce:           nonce,
		ProofCutoffTier: cutoffTier,
	})

	pt := cbmt.NewPartialTree(cbmt.PartialTreeConfig{
		NLeaves: uint16(len(leafData)),

		Hasher:   bcsha256.Hasher{},
		HashSize: bcsha256.HashSize,

		Nonce: nonce,

		ProofCutoffTier: cutoffTier,

		RootProofs: res.RootProof,
	})

	return pt, res
}

var fixtureLeafData = [][]byte{
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
	[]byte("eleven"),
	[]byte("twelve"),
	[]byte("thirteen"),
	[]byte("fourteen"),
	[]byte("fifteen"),
	[]byte("sixteen"),
	[]byte("seventeen"),
}
