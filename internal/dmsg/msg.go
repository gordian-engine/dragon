package dmsg

import (
	"crypto/x509"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

// ForwardJoinFromNetwork is a request for a forward join
// that gets passed back to the kernel.
//
// The dk package already depends on this package,
// so we declare this request type here.
type ForwardJoinFromNetwork struct {
	Msg dproto.ForwardJoinMessage

	// We received this request from an active peer,
	// so we track who sent it to us,
	// in order to not send it back to them.
	//
	// TODO: this should be a dcert.Chain instead.
	ForwarderCert *x509.Certificate
}

// ShuffleFromPeer is a shuffle message that a peer sent directly to us.
// It has to go back to the kernel,
// so that the view manager can handle it.
type ShuffleFromPeer struct {
	Src dcert.Chain

	Stream quic.Stream

	Msg dproto.ShuffleMessage
}

// ShuffleReplyFromPeer is a shuffle message that a peer sent
// in reply to us initiating a shuffle to them.
type ShuffleReplyFromPeer struct {
	Src dcert.Chain

	Msg dproto.ShuffleReplyMessage
}
