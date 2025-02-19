package dviewtest

import (
	"context"
	"errors"

	"dragon.example/dragon/dview"
)

type DenyingManager struct{}

func (DenyingManager) ConsiderJoin(
	context.Context, dview.ActivePeer,
) (dview.JoinDecision, error) {
	return dview.DisconnectAndIgnoreJoinDecision, nil
}

func (DenyingManager) AddPeering(
	context.Context, dview.ActivePeer,
) (*dview.ActivePeer, error) {
	return nil, errors.New("peering denied")
}

func (DenyingManager) RemoveActivePeer(context.Context, dview.ActivePeer) {}

func (DenyingManager) NActivePeers() int  { return 0 }
func (DenyingManager) NPassivePeers() int { return 0 }
