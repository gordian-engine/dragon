package dps

import (
	"crypto/x509"

	"github.com/quic-go/quic-go"
)

type Peer struct {
	Conn quic.Connection

	Admission, Disconnect, Shuffle quic.Stream
}

func (p Peer) toInternal() iPeer {
	pcs := p.Conn.ConnectionState().TLS.PeerCertificates

	return iPeer{
		Conn: p.Conn,

		Admission:  p.Admission,
		Disconnect: p.Disconnect,
		Shuffle:    p.Shuffle,

		CASPKI:   caSPKI(pcs[len(pcs)-1].RawSubjectPublicKeyInfo),
		LeafSPKI: leafSPKI(pcs[0].RawSubjectPublicKeyInfo),
	}
}

// iPeer is an internal representation of a peer.
type iPeer struct {
	Conn quic.Connection

	Admission, Disconnect, Shuffle quic.Stream

	CASPKI   caSPKI
	LeafSPKI leafSPKI
}

func (ip iPeer) ToPeer() Peer {
	return Peer{
		Conn: ip.Conn,

		Admission:  ip.Admission,
		Disconnect: ip.Disconnect,
		Shuffle:    ip.Shuffle,
	}
}

type PeerCertID struct {
	caSPKI   caSPKI
	leafSPKI leafSPKI
}

func PeerCertIDFromCerts(pcs []*x509.Certificate) PeerCertID {
	return PeerCertID{
		caSPKI:   caSPKI(pcs[len(pcs)-1].RawSubjectPublicKeyInfo),
		leafSPKI: leafSPKI(pcs[0].RawSubjectPublicKeyInfo),
	}
}
