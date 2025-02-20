package dps

import (
	"crypto/x509"

	"github.com/gordian-engine/dragon/internal/dproto"
)

// addRequest is a request to add a peer to the active peer set.
type addRequest struct {
	IPeer iPeer

	// No detail necessary in acknowledgement.
	Resp chan struct{}
}

type removeRequest struct {
	PCI PeerCertID

	// No detail necessary in acknowledgement.
	Resp chan struct{}
}

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
	ForwarderCert *x509.Certificate
}

type forwardJoinToNetwork struct {
	Msg dproto.ForwardJoinMessage

	// Exclude peers by their CA certificate's SPKI.
	Exclude map[string]struct{}
}
