package dpeerset

import (
	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dquic"
)

type Peer struct {
	Conn dquic.Conn

	Chain dcert.Chain
	AA    daddr.AddressAttestation

	// TODO: this could possibly be just a quic.SendStream,
	// as the read side happens in the peerInboundProcessor type,
	// and we must not interfere with that work.
	Admission dquic.Stream

	Removed <-chan struct{}
}

func (p Peer) toInternal() iPeer {
	return iPeer{
		Conn: p.Conn,

		Chain: p.Chain,
		AA:    p.AA,

		Admission: p.Admission,

		CACertHandle:   p.Chain.RootHandle,
		LeafCertHandle: p.Chain.LeafHandle,

		Removed: p.Removed,
	}
}

// iPeer is an internal representation of a peer.
// It contains some extra fields that seem worth calculating only once.
type iPeer struct {
	Conn dquic.Conn

	Chain dcert.Chain
	AA    daddr.AddressAttestation

	Admission dquic.Stream

	CACertHandle   dcert.CACertHandle
	LeafCertHandle dcert.LeafCertHandle

	Removed <-chan struct{}
}

func (ip iPeer) ToPeer() Peer {
	return Peer{
		Conn: ip.Conn,

		Chain: ip.Chain,
		AA:    ip.AA,

		Admission: ip.Admission,

		Removed: ip.Removed,
	}
}

type PeerCertID struct {
	leafHandle dcert.LeafCertHandle
	caHandle   dcert.CACertHandle
}

func PeerCertIDFromChain(chain dcert.Chain) PeerCertID {
	return PeerCertID{
		leafHandle: chain.LeafHandle,
		caHandle:   chain.RootHandle,
	}
}
