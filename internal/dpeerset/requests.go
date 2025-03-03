package dpeerset

import (
	"github.com/gordian-engine/dragon/internal/dprotoi"
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

type forwardJoinToNetwork struct {
	Msg dprotoi.ForwardJoinMessage

	// Exclude peers by their CA certificate's SPKI.
	Exclude map[string]struct{}
}

type initiatedShuffle struct {
	DstCASPKI string
	Entries   []dprotoi.ShuffleEntry
}
