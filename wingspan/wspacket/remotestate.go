package wspacket

import "iter"

// RemoteState is the state management related to a single peer.
//
// The type parameter D is the type of the "delta"
// that propagates from the [CentralState] to the [RemoteState].
//
// The methods on RemoteState are all called in Wingspan internals,
// and implementers can assume no methods are called concurrently.
type RemoteState[D any] interface {
	// Apply the update that was dispatched from the [CentralState].
	// Wingspan internals handle routing this request.
	ApplyUpdateFromLocal(D) error

	// If the peer for this state gave us new information,
	// the Wingspan internals mark it here first,
	// so that UpdateFromLocal is a redundant update.
	ApplyUpdateFromRemote(D) error

	// An iterator over the packets in the RemoteState
	// which have not yet been sent.
	//
	// Wingspan internals will not call any other method on RemoteState
	// while the iterator is active.
	//
	// It is possible that there may be many calls
	// to ApplyUpdateFromLocal or ApplyUpdateFromRemote
	// before UnsentPackets is called again.
	UnsentPackets() iter.Seq[Packet]
}
