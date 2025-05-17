package dbitset_test

import (
	"context"
	"io"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/internal/dbitset"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/stretchr/testify/require"
)

func TestSnappyCodec_roundTrip(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ls := dquictest.NewListenerSet(t, ctx, 2)
	c0, c1 := ls.Dial(t, 0, 1)

	s01, err := c0.OpenStream()
	require.NoError(t, err)

	_, err = s01.Write([]byte{0})
	require.NoError(t, err)

	s10, err := c1.AcceptStream(ctx)
	require.NoError(t, err)
	buf1 := make([]byte, 1)
	_, err = io.ReadFull(s10, buf1)
	require.NoError(t, err)
	require.Zero(t, buf1[0])

	var enc dbitset.SnappyEncoder
	var dec dbitset.SnappyDecoder

	rng := rand.New(rand.NewPCG(5, 10))

	for range 500 {
		sz := 2 + rng.UintN((1<<16)-2)
		idxs := rng.Perm(int(sz))
		setCount := rng.IntN(int(sz))

		bs := bitset.MustNew(sz)

		for _, v := range idxs[:setCount] {
			bs.Set(uint(v))
		}

		require.NoError(t, enc.SendBitset(s01, 10*time.Millisecond, bs))

		got := bitset.MustNew(sz)
		require.NoError(t, dec.ReceiveBitset(s10, 10*time.Millisecond, got))

		require.Truef(
			t,
			bs.Equal(got),
			"sent: %s\nrcvd: %s", bs, got,
		)
	}
}
