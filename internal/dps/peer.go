package dps

import (
	"crypto/x509"

	"github.com/quic-go/quic-go"
)

type Peer struct {
	Conn quic.Connection

	// TODO: first, these should probably all be quic.SendStream,
	// as the read side happens in the peerWorker type,
	// and we must not interfere with that work.
	//
	// Furthermore, while it is true that we only do one action at a time
	// on a worker goroutine,
	// it is plausible that two actions could happen concurrently.
	// For example, if two peers happen to independently pick each other
	// for a shuffle near the same instant in time,
	// two independent workers could both attempt to write to the same stream.
	// And even though the writes wouldn't be interleaved
	// (at least as long as they were single write calls),
	// independent write deadlines could be applied in the wrong order.
	//
	// We could try adding two different streams, so that each peer
	// has their own "I write a shuffle and you write the response" stream,
	// but it feels like that may be just papering over the problem.
	//
	// This basically only leaves the solution of wrapping the stream
	// with a protocol-level mutex.
	Admission, Disconnect, Shuffle quic.Stream
}

func (p Peer) toInternal() iPeer {
	// TODO: this should probably be VerifiedCertificates also.
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
