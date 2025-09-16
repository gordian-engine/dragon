package wspacket

import (
	"context"
	"errors"

	"github.com/gordian-engine/dragon/dpubsub"
)

// CentralState is the state management that is central to a session,
// related to but decoupled from any remote state.
//
// It has four type parameters:
//   - PktIn is the parsed but unprocessed packet from a peer
//   - PktOut is the outbound packet including its byte-level representation
//   - DeltaIn is the "stateless" representation of an incoming state change
//   - DeltaOut is the "stateless" representation of an outgoing state change
//
// The PktIn and DeltaIn types are separate for two primary reasons.
// First, the packet may be stateful with regard to the underlying stream,
// and the delta is intended to be stateless (has no regard to any single QUIC stream).
// Second, the delta may contain computed values that are necessary
// for the central state but which are not encoded in the packet.
//
// While this interface contains the methods necessary
// for integration with the [wingspan.Protocol],
// there is other functionality required outside of this interface.
//
// For instance, there must be an outbound delta [*dpubsub.Stream]
// associated with the CentralState
// and provided when creating a new Wingspan session.
type CentralState[
	PktIn any, PktOut OutboundPacket,
	DeltaIn, DeltaOut any,
] interface {
	// UpdateFromPeer updates the central state with
	// new information originating from a remote peer.
	//
	// If the delta does not add new information to the state,
	// this method must return [ErrRedundantUpdate].
	//
	// This method must return nil on success or [ErrRedundantUpdate]
	// if the packet contained no new information.
	// Any other error value is treated as a protocol violation,
	// which will result in a disconnection from the peer.
	UpdateFromPeer(context.Context, DeltaIn) error

	// NewOutboundRemoteState returns an OutboundRemoteState instance
	// that contains a copy of the state in the current central state,
	// and a Stream that is valid for the returned state.
	//
	// Returning the stream here avoids the possibility
	// of a data race between constructing the state
	// and observing the stream.
	NewOutboundRemoteState(context.Context) (
		OutboundRemoteState[PktIn, PktOut, DeltaIn, DeltaOut],
		*dpubsub.Stream[DeltaOut],
		error,
	)

	// NewInboundRemoteState returns a new [InboundRemoteState]
	// that contains a copy of the state in the current central state,
	// and a Stream that is valid for the returned state.
	//
	// Returning the stream here avoids the possibility
	// of a data race between constructing the state
	// and observing the stream.
	NewInboundRemoteState(context.Context) (
		InboundRemoteState[PktIn, DeltaIn, DeltaOut],
		*dpubsub.Stream[DeltaOut],
		error,
	)
}

// Returned from [CentralState.UpdateFromPeer]
// indicating that the delta did not add new information.
// This is a normal case when many peers are gossiping at once.
var ErrRedundantUpdate = errors.New("delta contained redundant data")
