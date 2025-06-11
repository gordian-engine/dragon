package dk

import (
	"time"

	"github.com/gordian-engine/dragon/dcert"
)

// forwardJoinCache holds recently seen forward join details.
//
// This is only used as part of [*Kernel.handleForwardJoinFromNetwork],
// whose state needs to persist between calls.
type forwardJoinCache struct {
	// Leaving this type as a struct,
	// so that we can simplify shrinking the Recent map as part of Purge
	// if we need to in the future.

	Recent map[dcert.LeafCertHandle]recentForwardJoin
}

type recentForwardJoin struct {
	// Expiration time in Unix milliseconds.
	// Millisecond is granular enough,
	// and we don't need a full time type for this.
	ExpireAt int64
	Chain    dcert.Chain
}

// Purge deletes all expired entries from the cache.
func (s *forwardJoinCache) Purge() {
	now := time.Now().Unix()

	for k, v := range s.Recent {
		if v.ExpireAt <= now {
			delete(s.Recent, k)
		}
	}

	if s.Recent == nil {
		s.Recent = make(map[dcert.LeafCertHandle]recentForwardJoin, 4) // Arbitrary size.
	}
}

// Has reports whether s has recently seen a forward join
// for the given chain.
func (s forwardJoinCache) Has(chain dcert.Chain) bool {
	_, ok := s.Recent[chain.LeafHandle]
	return ok
}

// Set marks the forward join as recently seen.
func (s forwardJoinCache) Set(chain dcert.Chain, expireDur time.Duration) {
	s.Recent[chain.LeafHandle] = recentForwardJoin{
		ExpireAt: time.Now().Add(expireDur).UnixMilli(),
		Chain:    chain,
	}
}
