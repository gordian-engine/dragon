package wingspan

import (
	"context"

	"github.com/gordian-engine/dragon/wingspan/internal/wsi"
)

// Session is a handle into a session object.
// Sessions are created through [*Protocol.NewSession].
//
// The type parameter D is the delta type, just as in [Protocol].
type Session[D any] struct {
	s      *wsi.Session[D]
	cancel context.CancelCauseFunc
}

// Cancel immediately stops the session,
// canceling any active send or receive streams.
func (s Session[D]) Cancel() {
	// TODO: use a sentinel error here.
	s.cancel(nil)
}
