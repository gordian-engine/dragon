package dviewtest

import (
	"context"
	"errors"

	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dview"
)

type DenyingManager struct{}

func (DenyingManager) ConsiderJoin(
	context.Context, dview.ActivePeer,
) (dview.JoinDecision, error) {
	return dview.DisconnectAndIgnoreJoinDecision, nil
}

func (DenyingManager) ConsiderNeighborRequest(
	context.Context, dview.ActivePeer,
) (bool, error) {
	return false, nil
}

func (DenyingManager) ConsiderForwardJoin(
	context.Context, daddr.AddressAttestation, dcert.Chain,
) (dview.ForwardJoinDecision, error) {
	return dview.ForwardJoinDecision{
		// Seems like we may as well continue forwarding in this test type.
		ContinueForwarding:  true,
		MakeNeighborRequest: false,
	}, nil
}

func (DenyingManager) AddPeering(
	context.Context, dview.ActivePeer,
) (*dview.ActivePeer, error) {
	return nil, errors.New("peering denied")
}

func (DenyingManager) RemoveActivePeer(context.Context, dview.ActivePeer) {}

func (DenyingManager) MakeOutboundShuffle(ctx context.Context) (dview.OutboundShuffle, error) {
	return dview.OutboundShuffle{}, errors.New("shuffle not supported in DenyingManager")
}

func (DenyingManager) NActivePeers() int  { return 0 }
func (DenyingManager) NPassivePeers() int { return 0 }
