package bcmerkletest

import (
	"testing"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle"
	"github.com/stretchr/testify/require"
)

type HasherFactory func() (h bcmerkle.Hasher, hashSize int)

func TestHasherCompliance(t *testing.T, f HasherFactory) {
	t.Run("leaf is deterministic", func(t *testing.T) {
		t.Parallel()

		h, sz := f()

		lc := bcmerkle.LeafContext{
			Nonce:     []byte("deterministic_nonce"),
			LeafIndex: [2]byte{1, 2},
		}

		dst01 := make([]byte, sz)
		h.Leaf([]byte("deterministic_data"), lc, dst01[:0])

		dst02 := make([]byte, sz)
		h.Leaf([]byte("deterministic_data"), lc, dst02[:0])

		require.Equal(t, dst01, dst02)
	})

	t.Run("leaf respects position", func(t *testing.T) {
		t.Parallel()

		h, sz := f()

		lc := bcmerkle.LeafContext{
			Nonce:     []byte("nonce"),
			LeafIndex: [2]byte{0, 1},
		}
		dst01 := make([]byte, sz)
		h.Leaf([]byte("hello"), lc, dst01[:0])

		lc.LeafIndex = [2]byte{1, 0}
		dst02 := make([]byte, sz)
		h.Leaf([]byte("hello"), lc, dst02[:0])

		require.NotEqual(t, dst01, dst02)
	})

	t.Run("leaf respects nonce", func(t *testing.T) {
		t.Parallel()

		h, sz := f()

		lc := bcmerkle.LeafContext{
			Nonce:     []byte("nonce_1"),
			LeafIndex: [2]byte{2, 4},
		}
		dst01 := make([]byte, sz)
		h.Leaf([]byte("fixed_data"), lc, dst01[:0])

		lc.Nonce = []byte("nonce_2")
		dst02 := make([]byte, sz)
		h.Leaf([]byte("fixed_data"), lc, dst02[:0])

		require.NotEqual(t, dst01, dst02)
	})
}
