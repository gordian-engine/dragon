package devaltest

import (
	"context"

	"dragon.example/dragon/deval"
)

type DenyingPeerEvaluator struct{}

func (DenyingPeerEvaluator) ConsiderJoin(context.Context, deval.Peer) deval.JoinDecision {
	return deval.DisconnectAndIgnoreJoinDecision
}
