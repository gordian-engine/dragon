package dk

import (
	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dview"
	"github.com/gordian-engine/dragon/internal/dprotoi"
	"github.com/quic-go/quic-go"
)

// JoinRequest is sent from the outer Node to the [Kernel],
// so that the Kernel can determine if we should
// ignore, reject, or accept the join request.
type JoinRequest struct {
	Peer dview.ActivePeer
	Msg  dprotoi.JoinMessage
	Resp chan JoinResponse
}

// JoinResponse is the response from the [Kernel] to the Node,
// indicating whether the join is acceptable.
type JoinResponse struct {
	Decision JoinDecision
}

// JoinDecision informs the Node on what to do
// with a Join message.
type JoinDecision uint8

const (
	// Disconnect without forwarding.
	// Kernel is responsible for handling forward join requests.
	DisconnectJoinDecision JoinDecision = iota

	// Accept the join request,
	// by responding with a Neighbor request.
	// Kernel is responsible for handling forward join requests.
	AcceptJoinDecision
)

// NeighborRequest is sent from the outer Node to the [Kernel],
// and the kernel reports back whether the neighbor request
// should be accepted or denied.
type NeighborDecisionRequest struct {
	Peer dview.ActivePeer

	Resp chan bool
}

// AddActivePeerRequest is sent from the outer Node to the [Kernel],
// telling the Kernel to add this peer to the active set.
//
// There are three circumstances where this can happen:
//  1. We were (re-)joining the p2p network,
//     and so we sent a Join message to another node.
//     That node we contacted, responded on the same connection
//     with a Neighbor message, and we completed that handshake.
//  2. Regardless of whether the node we contacted in 1 made a Neighbor request,
//     it send a Forward Join message to its active view peers
//     and one of them opened a connection to us,
//     and sent us a Neighbor request.
//  3. We were in another node's passive view,
//     and that node needed a new connection,
//     so they connected to us and directly opened sent a Neighbor message.
type AddActivePeerRequest struct {
	QuicConn quic.Connection

	Chain dcert.Chain

	AA daddr.AddressAttestation

	AdmissionStream quic.Stream

	Resp chan AddActivePeerResponse
}

// AddActivePeerResponse is the response from the [Kernel] to the Node,
// indicating whether the peer was accepted into the active set.
//
// If RejectReason is empty, the peer was accepted.
// Otherwise, the RejectReason can be sent to the remote peer.
type AddActivePeerResponse struct {
	RejectReason string
}
