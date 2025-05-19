package dbitset_test

import (
	"testing"

	"github.com/gordian-engine/dragon/internal/dbitset"
)

func TestSnappyCodec_roundTrip(t *testing.T) {
	t.Parallel()

	var enc dbitset.SnappyEncoder
	var dec dbitset.SnappyDecoder
	testCodec(t, &enc, &dec)
}
