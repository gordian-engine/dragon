package wspacket

import (
	"context"
	"errors"

	"github.com/gordian-engine/dragon/dpubsub"
)

// CentralState is the state management that is central to a session,
// related to but decoupled from any remote state.
//
// The type parameter D is the "delta" type
// that the central state emits to notify remote states of updates.
//
// While this interface contains the methods necessary
// for integration with the [wingspan.Protocol],
// there is other functionality required outside of this interface.
//
// For instance, there must be a "deltas" [*dpubsub.Stream]
// associated with the CentralState
// and provided when creating a new Wingspan session.
type CentralState[D any] interface {
	// UpdateFromPeer updates the central state with
	// new information originating from a remote peer.
	//
	// If the delta does not add new information to the state,
	// this method must return [ErrRedundantUpdate].
	UpdateFromPeer(context.Context, D) error

	// NewOutboundRemoteState returns an OutboundRemoteState instance
	// that contains a copy of the state in the current central state,
	// and a Stream that is valid for the returned state.
	//
	// Returning the stream here avoids the possibility
	// of a data race between constructing the state
	// and observing the stream.
	NewOutboundRemoteState(context.Context) (
		OutboundRemoteState[D], *dpubsub.Stream[D], error,
	)

	// NewInboundRemoteState returns a new [InboundRemoteState]
	// that contains a copy of the state in the current central state,
	// and a Stream that is valid for the returned state.
	//
	// Returning the stream here avoids the possibility
	// of a data race between constructing the state
	// and observing the stream.
	NewInboundRemoteState(context.Context) (
		InboundRemoteState[D], *dpubsub.Stream[D], error,
	)
}

// Returned from [CentralState.UpdateFromPeer]
// indicating that the delta did not add new information.
// This is a normal case when many peers are gossiping at once.
var ErrRedundantUpdate = errors.New("delta contained redundant data")
