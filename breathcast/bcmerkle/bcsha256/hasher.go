package bcsha256

import (
	"crypto/sha256"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle"
)

const HashSize = sha256.Size

// Hasher is a [bcmerkle.Hasher] backed by SHA256 hashes.
type Hasher struct{}

func (Hasher) Leaf(in []byte, c bcmerkle.LeafContext, dst []byte) {
	h := sha256.New()
	_, _ = h.Write(c.Nonce)
	_, _ = h.Write(c.LeafIndex[:])
	_, _ = h.Write([]byte("L."))
	_, _ = h.Write(in)
	h.Sum(dst)
}

func (Hasher) Node(left, right []byte, c bcmerkle.NodeContext, dst []byte) {
	h := sha256.New()
	_, _ = h.Write(c.Nonce)
	_, _ = h.Write(c.FirstLeafIndex[:])
	_, _ = h.Write([]byte("Hl."))
	_, _ = h.Write(left)
	_, _ = h.Write(c.LastLeafIndex[:])
	_, _ = h.Write([]byte("Hr."))
	_, _ = h.Write(right)
	h.Sum(dst)
}
