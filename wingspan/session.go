package wingspan

import (
	"context"

	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/wingspan/internal/wsi"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
)

// Session is a handle into a session object.
// Sessions are created through [*Protocol.NewSession].
//
// The type parameter D is the delta type, just as in [Protocol].
// The type parameter P is the packet type corresponding to a [PacketParser].
type Session[
	PktIn any, PktOut wspacket.OutboundPacket,
	DeltaIn, DeltaOut any,
] struct {
	s      *wsi.Session[PktIn, PktOut, DeltaIn, DeltaOut]
	cancel context.CancelCauseFunc
}

// AcceptStream adds the incoming stream to the session.
//
// It is a fatal error to call AcceptStream twice with the same stream.
func (s Session[PktIn, PktOut, DeltaIn, DeltaOut]) AcceptStream(
	ctx context.Context,
	conn dconn.Conn,
	rs dquic.ReceiveStream,
) error {
	return s.s.AcceptStream(ctx, conn, rs)
}

// Cancel immediately stops the session,
// canceling any active send or receive streams.
func (s Session[PktIn, PktOut, DeltaIn, DeltaOut]) Cancel() {
	// TODO: use a sentinel error here.
	s.cancel(nil)
}
