package wingspan

import (
	"context"

	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/wingspan/internal/wsi"
	"github.com/quic-go/quic-go"
)

// Session is a handle into a session object.
// Sessions are created through [*Protocol.NewSession].
//
// The type parameter D is the delta type, just as in [Protocol].
type Session[D any] struct {
	s      *wsi.Session[D]
	cancel context.CancelCauseFunc
}

// AcceptStream adds the incoming stream to the session.
//
// It is a fatal error to call AcceptStream twice with the same stream.
func (s Session[D]) AcceptStream(
	ctx context.Context,
	conn dconn.Conn,
	rs quic.ReceiveStream,
) error {
	return s.s.AcceptStream(ctx, conn, rs)
}

// Cancel immediately stops the session,
// canceling any active send or receive streams.
func (s Session[D]) Cancel() {
	// TODO: use a sentinel error here.
	s.cancel(nil)
}
