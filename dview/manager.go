package dview

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	"github.com/gordian-engine/dragon/internal/dproto"
)

// ActivePeer is a peer in the active view
// (peers we have a direct connection with).
type ActivePeer struct {
	// TODO: it might be better to have a narrower value
	// than an entire tls.ConnectionState.
	TLS tls.ConnectionState

	// TODO: this should contain an address attestation.

	// The address of our local listener.
	// Might be relevant if the system is configured with multiple listeners.
	LocalAddr net.Addr

	// The remote address observed.
	// TODO: this seems useless.
	// Consider the case of a peer dialing us
	// while using a different UDP port from its listener.
	// We should be sending an AdvertiseAddr on Join and Neighbor messages.
	RemoteAddr net.Addr
}

func (p ActivePeer) CACert() *x509.Certificate {
	pcs := p.TLS.PeerCertificates // TODO: this is probably wrong and needs to be .VerifiedCertificates.
	return pcs[len(pcs)-1]
}

// PassivePeer is a peer in the passive set
// (peers we know about, but are not directly connected with).
type PassivePeer struct {
	Addr string

	// TODO: this should contain an address attestation.

	// The trusted CA who signed this peer's leaf certificate.
	CACert *x509.Certificate
}

// Manager manages the set of active and passive peers.
//
// Methods on Manager are only intended to be called through the dragon kernel,
// which is to say that they will not be called concurrently.
type Manager interface {
	// ConsiderJoin evaluates whether a join request
	// should be disconnected without forwarding,
	// disconnected with forwarding,
	// or responded to with a neighbor request.
	//
	// This method accepts an ActivePeer because
	// there must be an already active connection
	// in order to have received a Join message in the first place.
	//
	// Instances should assume that the the provided peer
	// has already been confirmed to be in the
	// list of acceptable certificates.
	//
	// If the returned error is non-nil,
	// the decision should be treated as [DisconnectAndIgnoreJoinDecision]
	// regardless of the actual value.
	ConsiderJoin(context.Context, ActivePeer) (JoinDecision, error)

	// ConsiderForwardJoin evaluates whether an incoming Forward Join message
	// should continue to be propagated
	// and whether the current node should attempt to make a neighbor request.
	ConsiderForwardJoin(context.Context, dproto.ForwardJoinMessage) (
		ForwardJoinDecision, error,
	)

	// ConsiderNeighborRequest evaluates whether to accept
	// an incoming Neighbor request.
	//
	// The same notes in ConsiderJoin apply to ConsiderNeighborRequest.
	ConsiderNeighborRequest(context.Context, ActivePeer) (bool, error)

	// AddPeering attempts to commit the peer to the active set.
	// It is possible that we decided to accept multiple joins concurrently,
	// and after adding some of them, one that was considered accepted
	// was no longer able to be added to the active view.
	//
	// The evicted peer is only informative.
	// The Manager is expected to internally handle any logic around
	// moving the evicted peer from the active to passive view,
	// without the caller needing to invoke any other method.
	// However, the caller is responsible for closing any network streams
	// or freeing any other resources related to the evicted peer.
	AddPeering(context.Context, ActivePeer) (evicted *ActivePeer, err error)

	// RemoveActivePeer removes a given active peer from the active set.
	//
	// Currently, if the provided peer was not in the active set, RemoveActivePeer panics.
	RemoveActivePeer(context.Context, ActivePeer)

	MakeOutboundShuffle(context.Context) (OutboundShuffle, error)

	// TODO: MakeShuffleResponse and HandleShuffleResponse.

	// The number of active peers being managed.
	NActivePeers() int

	// The number of passive peers being managed.
	NPassivePeers() int

	// TODO: need a way to remove all active and passive peers
	// originating from a particular CA.

	// TODO: need a way to get a passive peer in order to re-fill active set.
	// This would probably only be called after removing peers.
}

// JoinDecision is the outcome of [Manager.ConsiderJoin].
// There is no explicit reply to a Join request:
// the contact node ignore the request altogether ([DisconnectAndIgnoreJoinDecision]);
// the contact node may choose not to join
// but to forward the notification to its active set ([DisconnectAndForwardJoinDecision]);
// or it may choose to accept the request by sending a Neighbor request
// and also send forward join messages to its active set ([AcceptJoinDecision]).
type JoinDecision uint8

const (
	DisconnectAndIgnoreJoinDecision JoinDecision = iota
	DisconnectAndForwardJoinDecision
	AcceptJoinDecision
)

// ForwardJoinDecision is the outcome of [Manager.ConsiderForwardJoin].
type ForwardJoinDecision struct {
	// If true, the system should decrement the forward join message's TTL
	// and continue forwarding it to peers.
	// Otherwise, the system should not propagate the message any further.
	//
	// The Manager implementation may disregard the TTL in this evaluation,
	// as the system will ignore this value when TTL=1
	// (indicating this was the last hop).
	ContinueForwarding bool

	// Whether the system should make a neighbor request to the joining node.
	MakeNeighborRequest bool
}

type OutboundShuffle struct {
	// TODO: how will the target peer and payload peers be represented?
}

// ErrAlreadyActiveCA should be returned by [Manager] implementations
// when attempting to add a peer who is already in the active set.
var ErrAlreadyActiveCA = errors.New("already have an active peer with the same CA")
