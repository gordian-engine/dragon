package dbitset_test

import (
	"testing"

	"github.com/gordian-engine/dragon/internal/dbitset"
)

func TestRawCodec_roundTrip(t *testing.T) {
	t.Parallel()

	var enc dbitset.RawEncoder
	var dec dbitset.RawDecoder
	testCodec(t, &enc, &dec)
}
