package wspacket

import "iter"

// OutboundRemoteState is the state management related to a single peer.
//
// The type parameter D is the type of the "delta"
// that propagates from the [CentralState] to the [OutboundRemoteState].
//
// The methods on OutboundRemoteState are all called in Wingspan internals,
// and implementers can assume no methods are called concurrently.
type OutboundRemoteState[D any] interface {
	// Apply the update that was dispatched from the [CentralState].
	// Wingspan internals handle routing this request.
	ApplyUpdateFromCentral(D) error

	// If the peer for this state gave us new information,
	// the Wingspan internals mark it here first,
	// so that UpdateFromLocal is a redundant update.
	ApplyUpdateFromPeer(D) error

	// An iterator over the packets in the OutboundRemoteState
	// which have not yet been sent.
	//
	// Wingspan internals will not call any other method on OutboundRemoteState
	// while the iterator is active.
	//
	// It is possible that there may be many calls
	// to ApplyUpdateFromCentral or ApplyUpdateFromPeer
	// before UnsentPackets is called again.
	UnsentPackets() iter.Seq[Packet]
}
