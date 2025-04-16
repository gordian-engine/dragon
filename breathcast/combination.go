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

// decodeCombinationIndex accepts n, k, and the combination index,
// and writes to the out bit set,
// setting the bits of the indices that the combination index represents.
func decodeCombinationIndex(n, k int, combIndex *big.Int, out *bitset.BitSet) {
	out.ClearAll()
	if k == 0 {
		// We already cleared out, so just stop here.
		return
	}

	var remaining, scratch big.Int
	remaining.Set(combIndex)

	curr := 0
	remainingPositions := k

	for remainingPositions > 0 {
		binomialCoefficient(n-curr-1, remainingPositions-1, &scratch)

		// While the remaining value is >= possible combinations, increment curr.
		for curr < n && remaining.Cmp(&scratch) >= 0 {
			remaining.Sub(&remaining, &scratch)
			curr++
			if curr < n {
				binomialCoefficient(n-curr-1, remainingPositions-1, &scratch)
			}
		}

		// We've found the next position that would give us this combination index.
		if curr < n {
			out.Set(uint(curr))

			curr++
			remainingPositions--
		}
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
