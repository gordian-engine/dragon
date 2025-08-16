package wspacket

import "errors"

// InboundRemoteState is the state associated with an inbound stream.
//
// Create an instance of InboundRemoteState with [CentralState.NewInboundRemoteState].
//
// Implementers may note that the sequence of calls for a single delta
// depends on the origin of the delta.
//
// If a different peer sends the delta, only ApplyUpdateFromCentral is called.
//
// If the peer associated with the state sends the Delta,
// CheckIncoming is called first to ensure the peer
// is not violating the protocol by sending the same packet twice,
// and also to short circuit unnecessary work
// if the peer sends a packet that we already received from another peer.
//
// If the packet received from the peer is new,
// and if the central state verifies and accepts the delta,
// then the session calls ApplyUpdateFromPeer.
//
// If another peer is concurrently sending the same packet,
// it is possible for ApplyUpdateFromCentral
// to be called between CheckIncoming and ApplyUpdateFromPeer.
type InboundRemoteState[D any] interface {
	// Apply the update that was dispatched from the [CentralState].
	// Wingspan internals handle routing this request.
	//
	// The purpose of the inbound state being aware of central state
	// is to affect the return value of CheckIncoming,
	// in order to avoid sending redundant values back to the central state.
	ApplyUpdateFromCentral(D) error

	// ApplyUpdateFromPeer indicates that the given delta
	// was accepted by the central state (or was noted as redundant
	// due to a concurrent update from another peer).
	//
	// For many implementations of InboundRemoteState,
	// ApplyUpdateFromPeer will be a no-op.
	//
	// It is possible although unlikely that a call to
	// ApplyUpdateFromCentral could occur before ApplyUpdateFromPeer,
	// so the implementation must handle that case gracefully,
	// returning nil.
	ApplyUpdateFromPeer(D) error

	// Determine if this is a packet we've seen before,
	// or if it is a packet this peer has already sent
	// (which is a protocol violation).
	//
	// Immediately after Wingspan internals parse a packet from a peer,
	// the parsed delta is passed to CheckIncoming.
	// This method must return [ErrAlreadyHavePacket],
	// [ErrDuplicateSentPacket], or nil.
	//
	// If CheckIncoming returns nil,
	// the Wingspan internals route the packet to
	// [OutboundRemoteState.AddUnverifiedFromPeer]
	// and to [CentralState.UpdateFromPeer].
	//
	// The implementation is responsible for ensuring
	// that multiple calls with the same delta
	// return ErrDuplicateSentPacket on the second or later calls.
	CheckIncoming(D) error
}

var (
	// Error to be returned from [InboundRemoteState.CheckIncoming]
	// when a peer sends a packet that was already observed
	// due to a call to ApplyUpdateFromCentral.
	// This is a normal occurrence which short-circuits some work.
	ErrAlreadyHavePacket = errors.New("already had packet")

	// Error to be returned from [InboundRemoteState.CheckIncoming]
	// when a peer sends the same packet more than once.
	// This is a protocol violation that will result in disconnection.
	ErrDuplicateSentPacket = errors.New("peer sent same packet twice")
)
