package cbmt_test

import (
	"fmt"
	"math/bits"
	"math/rand/v2"
	"testing"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
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

// This test isn't passing yet; we are using it to drive smaller, independent tests.
func xTestPartialTree_AddLeaf_sequence(t *testing.T) {
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
