package wspacket

import (
	"context"

	"github.com/gordian-engine/dragon/internal/dchan"
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
// For instance, there must be a "deltas" [*dchan.Multicast]
// associated with the CentralState
// and provided when creating a new Wingspan session.
type CentralState[D any] interface {
	// UpdateFromRemote updates the central state with
	// new information originating from a remote peer.
	UpdateFromRemote(context.Context, D) error

	// NewRemoteState returns a RemoteState instance
	// that contains a copy of the state in the current central state,
	// and a Multicast that is valid for the returned state.
	//
	// Returning the multicast here avoids the possibility
	// of a data race between constructing the state
	// and observing the multicast.
	NewRemoteState(context.Context) (RemoteState[D], *dchan.Multicast[D], error)
}
