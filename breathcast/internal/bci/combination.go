package bci

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/quic-go/quic-go"
)

// CombinationEncoder maintains internal state for encoding compressed bitsets.
// This internal state reduces allocations as bitsets are encoded.
//
// The zero value of CombinationEncoder is ready to use.
//
// CombinationEncoder is not safe for concurrent use.
type CombinationEncoder struct {
	// Buffer for bytes to write to wire.
	outBuf []byte

	// Temporary variables for calculating binomial coefficient.
	combIdx, scratch big.Int
}

// SendBitset writes the compressed form of bs to the given stream.
// The bitset's length (as reported by [*bitset.BitSet.Len])
// must be the same value the remote expects,
// or else the remote will decode a different value from what we encode here.
func (e *CombinationEncoder) SendBitset(
	s quic.SendStream,
	timeout time.Duration,
	bs *bitset.BitSet,
) error {
	k := e.calculateCombIdx(bs)

	// We need the out buffer to accommodate 4 bytes of metadata
	// plus the size of the combination index.
	ciByteCount := (e.combIdx.BitLen() + 7) / 8
	sz := 4 + ciByteCount
	if cap(e.outBuf) < sz {
		e.outBuf = make([]byte, sz)
	} else {
		e.outBuf = e.outBuf[:sz]
	}

	binary.BigEndian.PutUint16(e.outBuf[:2], k)
	binary.BigEndian.PutUint16(e.outBuf[2:4], uint16(ciByteCount))

	_ = e.combIdx.FillBytes(e.outBuf[4:])

	if err := s.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	if _, err := s.Write(e.outBuf); err != nil {
		return fmt.Errorf("failed to write bitset: %w", err)
	}

	return nil
}

func (e *CombinationEncoder) calculateCombIdx(bs *bitset.BitSet) uint16 {
	kk := int(bs.Count())
	k := uint16(kk)

	e.combIdx.SetUint64(0)

	prev := -1
	n := int(bs.Len())
	for u, ok := bs.NextSet(0); ok && int(u) < n; u, ok = bs.NextSet(u + 1) {
		i := int(u)
		remainingPositions := kk - 1

		for j := prev + 1; j < i; j++ {
			remainingNumbers := n - j - 1

			binomialCoefficient(remainingNumbers, remainingPositions, &e.scratch)
			e.combIdx.Add(&e.combIdx, &e.scratch)
		}

		prev = i
		kk--
	}

	return k
}

// CombinationDecoder maintains internal state for decoding compressed bitsets.
// This internal state reduces allocations as bitsets are decoded.
//
// The zero value of CombinationDecoder is ready to use.
//
// CombinationDecoder is not safe for concurrent use.
type CombinationDecoder struct {
	inBuf []byte

	combIdx, remaining, scratch big.Int
}

// ReceiveBitset reads a compressed bitset from the given stream,
// and sets the bs input argument to match that value.
//
// The read deadline for the bitset is determined by the timeout argument.
// If timeout is positive, that duration is used for the deadline.
// Otherwise, the read deadline is cleared
// and the read will block until the data is received
// or the read is canceled.
//
// The bitset's length (as reported by [*bitset.BitSet.Len])
// must be the same value the remote expects,
// or else the remote will decode a different value from what we encode here.
func (d *CombinationDecoder) ReceiveBitset(
	s quic.ReceiveStream,
	timeout time.Duration,
	bs *bitset.BitSet,
) error {
	var meta []byte
	if cap(d.inBuf) < 4 {
		// Should only hit this case when d is not yet initialized.
		d.inBuf = make([]byte, 4)
		meta = d.inBuf
	} else {
		meta = d.inBuf[:4]
	}

	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if err := s.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set read deadline for compressed bitset: %w", err)
	}
	if _, err := io.ReadFull(s, meta[:]); err != nil {
		return fmt.Errorf("failed to read bitset metadata: %w", err)
	}

	k := binary.BigEndian.Uint16(meta[:2])
	combIdxSize := binary.BigEndian.Uint16(meta[2:])

	// TODO: there is probably some reasonable limit on combIdxSize
	// that we should enforce here.
	// I haven't crunched the numbers to figure out what that limit is.

	var combBytes []byte
	if cap(d.inBuf) < int(combIdxSize) {
		d.inBuf = make([]byte, combIdxSize)
		combBytes = d.inBuf
	} else {
		combBytes = d.inBuf[:combIdxSize]
	}
	if _, err := io.ReadFull(s, combBytes); err != nil {
		return fmt.Errorf("failed to read bitset data: %w", err)
	}

	d.combIdx.SetBytes(combBytes)
	d.decodeCombIdx(int(k), bs)

	return nil
}

func (d *CombinationDecoder) decodeCombIdx(k int, bs *bitset.BitSet) {
	bs.ClearAll()
	if k == 0 {
		// We already cleared out, so just stop here.
		return
	}

	remaining := &d.combIdx
	scratch := &d.scratch

	n := int(bs.Len())
	curr := 0
	remainingPositions := k

	for remainingPositions > 0 {
		binomialCoefficient(n-curr-1, remainingPositions-1, &d.scratch)

		for curr < n && remaining.Cmp(scratch) >= 0 {
			remaining.Sub(remaining, scratch)
			curr++
			if curr < n {
				binomialCoefficient(n-curr-1, remainingPositions-1, scratch)
			}
		}

		// We've found the next position that would give us this combination index.
		if curr < n {
			bs.Set(uint(curr))

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
