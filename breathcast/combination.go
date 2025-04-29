package breathcast

import (
	"fmt"
	"math/big"

	"github.com/bits-and-blooms/bitset"
)

// Most of this code is from Gordian's gcrypto/gblsminsig package,
// which uses a similar scheme to indicate indices of keys
// present in an aggregated signature.

// calculateCombinationIndex writes the combination index of bs to the out argument.
// totalChunks is the number of chunks,
// and bs indicates which indices in the input set are to be represented.
//
// The out argument is an argument, not a return value,
// so that already allocated bytes can be reused.
func calculateCombinationIndex(totalChunks int, bs *bitset.BitSet, out *big.Int) {
	k := int(bs.Count())

	out.SetUint64(0)
	var scratch big.Int

	prev := -1
	for u, ok := bs.NextSet(0); ok && int(u) < totalChunks; u, ok = bs.NextSet(u + 1) {
		i := int(u)
		remainingPositions := k - 1

		for j := prev + 1; j < i; j++ {
			remainingNumbers := totalChunks - j - 1

			binomialCoefficient(remainingNumbers, remainingPositions, &scratch)
			out.Add(out, &scratch)
		}

		prev = i
		k--
	}
}

// The binomial coefficient ("n choose k")
// is the number of ways to choose k elements from a set of n elements,
// where selection order does not matter.
//
// We use this when determining the combination index,
// which is important for sending compressed bit sets
// to peers during broadcasts.
func binomialCoefficient(n, k int, out *big.Int) {
	if k > n {
		// The standard library returns zero here,
		// but this is a caller bug in our case.
		panic(fmt.Errorf("BUG: k(%d) > n(%d): caller needs to prevent this case", k, n))
	}

	if k == 0 || k == n {
		// Unlikely early return.
		out.SetUint64(1)
		return
	}

	// Assume the standard library is an optimized calculation.
	// We could possibly do better if we use some caching,
	// but let's hold off on that until profiling shows it worthwhile.
	out.Binomial(int64(n), int64(k))
}
