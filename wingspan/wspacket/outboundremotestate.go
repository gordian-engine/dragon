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
	//
	// An update from the central state indicates a new packet
	// that should be included in the UnsentPackets output,
	// unless there was a prior call to AddUnverifiedFromPeer
	// that matches the update.
	// In that case, the state should treat the delta
	// as though the peer already has it.
	ApplyUpdateFromCentral(D) error

	// AddUnverifiedFromPeer is called after successfully parsing
	// a delta from a packet, on the corresponding inbound worker,
	// but before Wingspan internals pass the delta
	// to the [CentralState] for verification.
	//
	// The implementation should treat optimistically accumulate
	// delta values in a buffer, removing entries upon
	// a corresponding call to ApplyUpdateFromCentral.
	//
	// In the event that the peer provides an invalid delta,
	// the session will stop using this state value
	// once the delta is determined to be invalid
	// (implying that the peer cannot be trusted).
	//
	// The implementation must gracefully handle an unverified delta
	// arriving after a call to ApplyUpdateFromCentral,
	// although that case is unlikely.
	AddUnverifiedFromPeer(D)

	// An iterator over the packets in the OutboundRemoteState
	// which have not yet been sent.
	//
	// Wingspan internals will not call ApplyUpdateFromCentral
	// while the iterator is active,
	// but AddUnverifiedFromPeer may be called
	// (which ought to be fine since
	// that should not affect the iteration).
	//
	// It is possible that there may be many calls
	// to ApplyUpdateFromCentral or AddUnverifiedFromPeer
	// before UnsentPackets is called again.
	UnsentPackets() iter.Seq[Packet]
}
