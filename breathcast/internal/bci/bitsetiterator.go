package bci

import (
	"iter"
	"sync"
	"sync/atomic"

	"github.com/bits-and-blooms/bitset"
)

// An arbitrarily chosen set of prime numbers under 1000,
// for choosing a coprime number for pseudorandom iteration
// over bitsets.
var primes = [...]uint{
	7, 17, 41, 89, 137, 191, 239, 257, 311, 389, 419,
	467, 541, 593, 643, 701, 797, 821, 887, 941, 997,
}

// A package-level shared seed value.
// Code in this package uses atomic access of the value,
// and the seed determines both indices into the primes array
// and starting index in bitset iteration.
var globalSeed uint64

// Pool for mutable bitsets.
// We need mutable bitsets in order to correctly track
// which bits we may still visit.
// We expect general "clusters" of usage,
// in particular as we are broadcasting data,
// because we do not want to send all data chunks in the same order;
// that would be inefficient use of the network if all peers
// are all broadcasting the same chunk at a given instant in time.
var bsPool sync.Pool

// ClearBit is the type returned in the [RandomClearBitIterator].
// We use a dedicated type here as opposed to a simple uint
// so that we can expose the [*ClearBit.InPlaceUnion] method.
type ClearBit struct {
	Idx uint
	bs  *bitset.BitSet

	dirty bool
}

// InPlaceUnion updates b to be the union of b and x.
// The input argument is not modified or retained.
// Any set bits in x will be skipped in following iterations through b.
//
// In most use cases there will be a separate "tracking" bitset
// that also needs updated.
func (b *ClearBit) InPlaceUnion(x *bitset.BitSet) {
	b.bs.InPlaceUnion(x)

	// Don't do bookkeeping in here.
	// Simply signal to the iterator code that it is outdated.
	b.dirty = true
}

// RandomClearBitIterator iterates over the cleared bits in bs
// in a pseudorandom order.
// The ClearBit return type has an [*ClearBit.InPlaceUnion] method
// which can be used to avoid iterating certain bits
// in this sequence of the current iteration.
func RandomClearBitIterator(bs *bitset.BitSet) iter.Seq[*ClearBit] {
	x := bsPool.Get()
	var local *bitset.BitSet
	if x == nil {
		local = bs.Clone()
	} else {
		local = x.(*bitset.BitSet)
		bs.CopyFull(local)
	}

	return func(yield func(*ClearBit) bool) {
		defer bsPool.Put(local)

		sz := local.Len()
		remaining := sz - local.Count()
		if remaining == 0 {
			// Unlikely early return case.
			return
		}

		// Finding a coprime value to the bitset's length
		// allows us to effectively find a pseudorandom order of iteration.
		stride := getCoprime(sz)

		// When we land on an already set bit,
		// we don't want to simply continue,
		// as that could be very inefficient for large, sparse bitsets.
		// So, we track the halfway index in order to search
		// the larger part of the bitset.
		// We could possibly be more efficient in the search
		// if we tracked the first and last cleared bit,
		// but that is moderately more complex and doesn't seem worth it yet.
		halfIdx := sz / 2

		cb := &ClearBit{
			Idx: uint(atomic.AddUint64(&globalSeed, 1)) % sz,

			bs: local,
		}

		for {
			if local.Test(cb.Idx) {
				// We landed on a set bit, so we have to find a clear bit.
				// We are going to present the location of the set bit
				// as the current position, but we are going to continue iterating
				// with the original/current cb.Idx,
				// so that we don't do anything weird where we end up earlier in our sequence
				// and have to re-seek more times.
				oldIdx := cb.Idx

				var ok bool
				if oldIdx < halfIdx {
					// Scan forward first to cover more bits.
					cb.Idx, ok = local.NextClear(oldIdx)
					if !ok {
						cb.Idx, _ = local.PreviousClear(oldIdx)
					}
				} else {
					// Scan backward first.
					cb.Idx, ok = local.PreviousClear(oldIdx)
					if !ok {
						cb.Idx, _ = local.NextClear(oldIdx)
					}
				}

				if !yield(cb) {
					return
				}
				local.Set(cb.Idx)
				cb.Idx = oldIdx
			} else {
				// We landed on a clear bit, so we can yield directly.
				if !yield(cb) {
					return
				}
				local.Set(cb.Idx)
			}

			if cb.dirty {
				remaining = sz - local.Count()
			} else {
				remaining--
			}

			if remaining == 0 {
				// We've exhausted all the bits.
				return
			}

			cb.Idx = (cb.Idx + stride) % sz
		}
	}
}

// getCoprime returns a pseudorandomly selected prime number
// that is coprime to bsLen.
func getCoprime(bsLen uint) uint {
	for {
		seed := atomic.AddUint64(&globalSeed, 1)
		coprime := primes[seed%uint64(len(primes))]
		if bsLen%coprime == 0 {
			continue
		}

		return coprime
	}
}
