package devaltest

import (
	"context"

	"dragon.example/dragon/deval"
)

// DenyingPeerEvaluator denies all requests.
type DenyingPeerEvaluator struct{}

func (DenyingPeerEvaluator) ConsiderJoin(context.Context, deval.Peer) deval.JoinDecision {
	return deval.DisconnectAndIgnoreJoinDecision
}
