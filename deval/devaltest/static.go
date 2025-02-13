package devaltest

import (
	"context"

	"dragon.example/dragon/deval"
)

// StaticPeerEvaluator satisfies [Deval.PeerEvaluator]
// by returning the values set on corresponding fields.
//
// The interface methods that return an error
// are all hardcoded to return nil errors.
type StaticPeerEvaluator struct {
	ConsiderJoinDecision deval.JoinDecision
}

func (s *StaticPeerEvaluator) ConsiderJoin(context.Context, deval.Peer) (deval.JoinDecision, error) {
	return s.ConsiderJoinDecision, nil
}
