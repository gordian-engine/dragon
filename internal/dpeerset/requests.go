package dpeerset

import (
	"github.com/gordian-engine/dragon/dcert"
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

// checkConnAddrRequest is a request to see if there is an existing connection
// matching the given NetAddr.
type checkConnAddrRequest struct {
	// The String() portion of [net.Addr] to match.
	NetAddr string

	// Whether it was present.
	Resp chan bool
}

// checkConnChainRequest is a request to see if there is an existing connection
// matching the given chain.
type checkConnChainRequest struct {
	Chain dcert.Chain

	// Whether it was present.
	Resp chan bool
}

type forwardJoinToNetwork struct {
	Msg dprotoi.ForwardJoinMessage

	// Exclude peers by their CA certificate raw subject public key info.
	Exclude map[dcert.CACertHandle]struct{}
}

type initiatedShuffle struct {
	DstCACertHandle dcert.CACertHandle

	Entries []dprotoi.ShuffleEntry
}
