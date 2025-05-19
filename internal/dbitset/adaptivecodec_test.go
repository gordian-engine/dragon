package dbitset_test

import (
	"testing"

	"github.com/gordian-engine/dragon/internal/dbitset"
)

func TestAdaptiveCodec_roundTrip(t *testing.T) {
	t.Parallel()
	var enc dbitset.AdaptiveEncoder
	var dec dbitset.AdaptiveDecoder
	testCodec(t, &enc, &dec)
}
