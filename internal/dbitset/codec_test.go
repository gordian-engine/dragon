package dbitset_test

import (
	"context"
	"io"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/dquic/dquictest"
	"github.com/stretchr/testify/require"
)

// testCodec provides a unified approach to testing codec implementations.
func testCodec(
	t *testing.T,
	enc interface {
		SendBitset(dquic.SendStream, time.Duration, *bitset.BitSet) error
	},
	dec interface {
		ReceiveBitset(dquic.ReceiveStream, time.Duration, *bitset.BitSet) error
	},
) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ls := dquictest.NewListenerSet(t, ctx, 2)
	c0, c1 := ls.Dial(t, 0, 1)

	s01, err := c0.OpenStreamSync(ctx)
	require.NoError(t, err)

	_, err = s01.Write([]byte{0})
	require.NoError(t, err)

	s10, err := c1.AcceptStream(ctx)
	require.NoError(t, err)
	buf1 := make([]byte, 1)
	_, err = io.ReadFull(s10, buf1)
	require.NoError(t, err)
	require.Zero(t, buf1[0])

	// Arbitrary seed values,
	// but we want them to be the same across all codec implementations.
	rng := rand.New(rand.NewPCG(400, 500))

	// We actually do want to minimize allocations during this test too.
	// It makes a measurable difference.
	var idxs []int
	srcWords := make([]uint64, 0, 8*1024)
	dstWords := make([]uint64, 0, 8*1024)

	for range 500 {
		sz := 2 + rng.UintN((1<<16)-2)
		if cap(idxs) < int(sz) {
			idxs = make([]int, sz)
		} else {
			idxs = idxs[:sz]
		}
		for i := range idxs {
			idxs[i] = i
		}
		rng.Shuffle(int(sz), func(i, j int) {
			idxs[i], idxs[j] = idxs[j], idxs[i]
		})

		setCount := rng.IntN(int(sz))

		// There isn't a simple way to right-size a bitset,
		// so we initialize a new instance from the backing uint64 slice
		// and then toggle a bit to set it to the right length.
		clear(srcWords[:sz/8])
		bs := bitset.From(srcWords[:0])
		bs.Set(sz)
		bs.Clear(sz)

		for _, v := range idxs[:setCount] {
			bs.Set(uint(v))
		}

		require.NoError(t, enc.SendBitset(s01, 10*time.Millisecond, bs))

		clear(dstWords[:sz/8])
		got := bitset.From(dstWords[:0])
		got.Set(sz)
		got.Clear(sz)

		require.NoError(t, dec.ReceiveBitset(s10, 10*time.Millisecond, got))

		require.Truef(
			t,
			bs.Equal(got),
			"sent: %s\nrcvd: %s", bs, got,
		)
	}
}
