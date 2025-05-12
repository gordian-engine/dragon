package bci_test

import (
	"slices"
	"testing"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/breathcast/internal/bci"
	"github.com/stretchr/testify/require"
)

const bitIteratorCheckCount = 8

func TestRandomClearBitIterator_differentOrder(t *testing.T) {
	t.Parallel()

	// With 98 clear bits, it's virtually impossible
	// that a relatively small set of iterations would go in the same order.
	bs := bitset.MustNew(100)
	bs.Set(10)
	bs.Set(20)

	ord1 := make([]uint, 0, 98)
	for cb := range bci.RandomClearBitIterator(bs) {
		ord1 = append(ord1, cb.Idx)
	}

	got := make([]uint, 0, 98)
	for range bitIteratorCheckCount {
		got = got[:0]
		for cb := range bci.RandomClearBitIterator(bs) {
			got = append(got, cb.Idx)
		}

		require.ElementsMatch(t, ord1, got)
		require.NotEqual(t, ord1, got)
	}
}

func TestRandomClearBitIterator_InPlaceUnion(t *testing.T) {
	t.Parallel()

	bs := bitset.MustNew(32)
	bs.Set(4)

	allSet := bitset.MustNew(32)
	allSet.FlipRange(0, 32)

	for range bitIteratorCheckCount {
		iters := 0
		for cb := range bci.RandomClearBitIterator(bs) {
			iters++

			// Unioning with an all-set bitset
			// causes iteration to end.
			cb.InPlaceUnion(allSet)
		}

		require.Equal(t, 1, iters)
	}
}

func TestRandomClearBitIterator_onlyVisitsClear(t *testing.T) {
	t.Parallel()

	const sz = bitIteratorCheckCount * 5
	visited := make([]uint, 0, sz)
	for i := range bitIteratorCheckCount {
		bs := bitset.MustNew(sz)
		bs.Set(uint(i))

		visited = visited[:0]
		for cb := range bci.RandomClearBitIterator(bs) {
			visited = append(visited, cb.Idx)
		}

		require.Len(t, visited, sz-1)
		require.NotContains(t, visited, uint(i)) // Doesn't have the one bit we set.

		// There were no duplicate visits in the list.
		slices.Sort(visited)
		visited = slices.Compact(visited)
		require.Len(t, visited, sz-1)
	}
}
