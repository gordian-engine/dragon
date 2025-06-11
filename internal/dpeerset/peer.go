package dpeerset

import (
	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/quic-go/quic-go"
)

type Peer struct {
	Conn quic.Connection

	Chain dcert.Chain
	AA    daddr.AddressAttestation

	// TODO: this could possibly be just a quic.SendStream,
	// as the read side happens in the peerInboundProcessor type,
	// and we must not interfere with that work.
	Admission quic.Stream
}

func (p Peer) toInternal() iPeer {
	return iPeer{
		Conn: p.Conn,

		Chain: p.Chain,
		AA:    p.AA,

		Admission: p.Admission,

		CACertHandle:   p.Chain.RootHandle,
		LeafCertHandle: p.Chain.LeafHandle,
	}
}

// iPeer is an internal representation of a peer.
// It contains some extra fields that seem worth calculating only once.
type iPeer struct {
	Conn quic.Connection

	Chain dcert.Chain
	AA    daddr.AddressAttestation

	Admission quic.Stream

	CACertHandle   dcert.CACertHandle
	LeafCertHandle dcert.LeafCertHandle
}

func (ip iPeer) ToPeer() Peer {
	return Peer{
		Conn: ip.Conn,

		Chain: ip.Chain,
		AA:    ip.AA,

		Admission: ip.Admission,
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
