package bcsha256_test

import (
	"testing"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcmerkletest"
	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
)

func TestCompliance(t *testing.T) {
	t.Parallel()

	bcmerkletest.TestHasherCompliance(t, func() (bcmerkle.Hasher, int) {
		return bcsha256.Hasher{}, bcsha256.HashSize
	})
}
