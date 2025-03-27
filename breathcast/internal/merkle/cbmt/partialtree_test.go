package cbmt_test

import (
	"fmt"
	"testing"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/stretchr/testify/require"
)

func TestNewPartialTree(t *testing.T) {
	t.Parallel()

	leafData := [][]byte{
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

	for nl := uint16(2); nl < 18; nl++ {
		for c := uint8(0); c < 3; c++ {
			t.Run(fmt.Sprintf("nLeaves = %d, cutoff tier = %d", nl, c), func(t *testing.T) {
				t.Parallel()

				fullTree := cbmt.NewEmptyTree(nl, bcsha256.HashSize)

				res := fullTree.Populate(leafData[:nl], cbmt.PopulateConfig{
					Hasher:          bcsha256.Hasher{},
					Nonce:           []byte(t.Name()),
					ProofCutoffTier: c,
				})

				pt := cbmt.NewPartialTree(nl, bcsha256.HashSize, c, res.RootProof)
				require.NotNil(t, pt)

				// TODO: we should actually interact with the partial tree.
				// Asserting that the returned tree is valid is insufficient.
			})
		}
	}
}
