package dmsg

import (
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/internal/dprotoi"
	"github.com/quic-go/quic-go"
)

const (
	// Application error code used when closing a connection
	// due to it being removed from the active view.
	RemovingFromActiveView quic.ApplicationErrorCode = 0x188E59FF
)

// ForwardJoinFromNetwork is a request for a forward join
// that gets passed back to the kernel.
//
// The dk package already depends on this package,
// so we declare this request type here.
type ForwardJoinFromNetwork struct {
	Msg dprotoi.ForwardJoinMessage

	// We received this request from an active peer,
	// so we track who sent it to us,
	// in order to not send it back to them.
	ForwarderChain dcert.Chain
}

// ShuffleFromPeer is a shuffle message that a peer sent directly to us.
// It has to go back to the kernel,
// so that the view manager can handle it.
type ShuffleFromPeer struct {
	Src dcert.Chain

	Stream quic.Stream

	Msg dprotoi.ShuffleMessage
}

// ShuffleReplyFromPeer is a shuffle message that a peer sent
// in reply to us initiating a shuffle to them.
type ShuffleReplyFromPeer struct {
	Src dcert.Chain

	Msg dprotoi.ShuffleReplyMessage
}
