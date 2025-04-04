package dtest

import (
	"crypto/sha256"
	"math/rand/v2"
	"testing"
)

// RandomDataForTest returns a byte slice of size sz
// containing pseudorandom data, derived from a seed based on the test name.
func RandomDataForTest(t *testing.T, sz int) []byte {
	// Sha256 happens to be the right size for the chacha8 seed,
	// and this fits well anyway since that means
	// we are not limited by the length of any particular test name.
	seed := sha256.Sum256([]byte(t.Name()))
	chacha := rand.NewChaCha8(seed)

	out := make([]byte, sz)

	if _, err := chacha.Read(out); err != nil {
		panic(err)
	}

	return out
}
