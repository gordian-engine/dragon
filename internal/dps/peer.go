package dps

import (
	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/quic-go/quic-go"
)

type Peer struct {
	Conn quic.Connection

	Chain dcert.Chain
	AA    daddr.AddressAttestation

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
	return iPeer{
		Conn: p.Conn,

		Chain: p.Chain,
		AA:    p.AA,

		Admission:  p.Admission,
		Disconnect: p.Disconnect,
		Shuffle:    p.Shuffle,

		CASPKI:   caSPKI(p.Chain.Root.RawSubjectPublicKeyInfo),
		LeafSPKI: leafSPKI(p.Chain.Leaf.RawSubjectPublicKeyInfo),
	}
}

// iPeer is an internal representation of a peer.
type iPeer struct {
	Conn quic.Connection

	Chain dcert.Chain
	AA    daddr.AddressAttestation

	Admission, Disconnect, Shuffle quic.Stream

	CASPKI   caSPKI
	LeafSPKI leafSPKI
}

func (ip iPeer) ToPeer() Peer {
	return Peer{
		Conn: ip.Conn,

		Chain: ip.Chain,
		AA:    ip.AA,

		Admission:  ip.Admission,
		Disconnect: ip.Disconnect,
		Shuffle:    ip.Shuffle,
	}
}

type PeerCertID struct {
	leafSPKI leafSPKI
	caSPKI   caSPKI
}

func PeerCertIDFromChain(chain dcert.Chain) PeerCertID {
	return PeerCertID{
		leafSPKI: leafSPKI(chain.Leaf.RawSubjectPublicKeyInfo),
		caSPKI:   caSPKI(chain.Root.RawSubjectPublicKeyInfo),
	}
}
