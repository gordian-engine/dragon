package devaltest

import (
	"context"

	"dragon.example/dragon/deval"
)

// StaticPeerEvaluator satisfies [Deval.PeerEvaluator]
// by returning the values set on corresponding fields.
type StaticPeerEvaluator struct {
	ConsiderJoinDecision deval.JoinDecision
}

func (s *StaticPeerEvaluator) ConsiderJoin(context.Context, deval.Peer) deval.JoinDecision {
	return s.ConsiderJoinDecision
}
