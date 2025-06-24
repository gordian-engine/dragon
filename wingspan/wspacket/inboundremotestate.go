package wspacket

import "errors"

// InboundRemoteState is the state associated with an inbound stream.
//
// Create an instance of InboundRemoteState with [CentralState.NewInboundRemoteState].
type InboundRemoteState[D any] interface {
	// Apply the update that was dispatched from the [CentralState].
	// Wingspan internals handle routing this request.
	//
	// The purpose of the inbound state being aware of central state
	// is to affect the return value of CheckIncoming,
	// in order to avoid sending redundant values back to the central state.
	ApplyUpdateFromCentral(D) error

	// If the peer for this state gave us new information,
	// the Wingspan internals mark it here first,
	// so that UpdateFromCentral is a redundant update.
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
	// After Wingspan internals parse a packet from a peer,
	// the parsed delta is passed to CheckIncoming.
	// This method must return [ErrAlreadyHavePacket],
	// [ErrDuplicateSentPacket], or nil.
	//
	// The implementation is responsible for ensuring
	// that multiple calls with the same delta
	// return ErrDuplicateSentPacket on the second or later calls.
	CheckIncoming(D) error
}

var (
	// Error to be returned from [InboundRemoteState.CheckIncoming]
	// when a peer sends a packet that we already had.
	// This is a normal occurrence which short-circuits some work.
	ErrAlreadyHavePacket = errors.New("already had packet")

	// Error to be returned from [InboundRemoteState.CheckIncoming]
	// when a peer sends a packet that the same peer already sent.
	// This is a protocol violation that will result in disconnection.
	ErrDuplicateSentPacket = errors.New("peer sent same packet twice")
)
