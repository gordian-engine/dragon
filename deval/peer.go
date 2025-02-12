package deval

import (
	"context"
	"crypto/tls"
	"net"
)

// Peer is a candidate peer for evaluation through [PeerEvaluator].
type Peer struct {
	TLS tls.ConnectionState

	// The address of our local listener.
	// Might be relevant if the system is configured with multiple listeners.
	LocalAddr net.Addr

	// The remote address observed.
	// TODO: cross-reference this with quic.ClientHelloInfo,
	// as it is possible
	RemoteAddr net.Addr
}

type PeerEvaluator interface {
	// ConsiderJoin evaluates whether a join request
	// should be disconnected without forwarding,
	// disconnected with forwarding,
	// or responded to with a neighbor request.
	ConsiderJoin(context.Context, Peer) JoinDecision
}

// JoinDecision is the outcome of [PeerEvaluator.ConsiderJoin].
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
