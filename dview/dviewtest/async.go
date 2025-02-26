package dviewtest

import (
	"context"

	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dview"
)

type AsyncManagerMock struct {
	ConsiderJoinCh            chan ConsiderJoinRequest
	ConsiderForwardJoinCh     chan ConsiderForwardJoinRequest
	ConsiderNeighborRequestCh chan ConsiderNeighborRequest
	AddActivePeerCh           chan AddActivePeerRequest
	MakeOutboundShuffleCh     chan MakeOutboundShuffleRequest
	MakeShuffleResponseCh     chan MakeShuffleResponseRequest
	HandleShuffleResponseCh   chan HandleShuffleResponseRequest

	// Keys are the CA cert SPKI for both of these maps.
	ActivePeers  map[string]dview.ActivePeer
	PassivePeers map[string]dview.PassivePeer
}

func NewAsyncManagerMock() *AsyncManagerMock {
	return &AsyncManagerMock{
		ConsiderJoinCh:            make(chan ConsiderJoinRequest),
		ConsiderForwardJoinCh:     make(chan ConsiderForwardJoinRequest),
		ConsiderNeighborRequestCh: make(chan ConsiderNeighborRequest),
		AddActivePeerCh:           make(chan AddActivePeerRequest),
		MakeOutboundShuffleCh:     make(chan MakeOutboundShuffleRequest),
		MakeShuffleResponseCh:     make(chan MakeShuffleResponseRequest),
		HandleShuffleResponseCh:   make(chan HandleShuffleResponseRequest),

		ActivePeers:  map[string]dview.ActivePeer{},
		PassivePeers: map[string]dview.PassivePeer{},
	}
}

func (m *AsyncManagerMock) ConsiderJoin(
	ctx context.Context, p dview.ActivePeer,
) (dview.JoinDecision, error) {
	resp := make(chan dview.JoinDecision, 1)
	m.ConsiderJoinCh <- ConsiderJoinRequest{
		P:    p,
		Resp: resp,
	}

	return <-resp, nil
}

func (m *AsyncManagerMock) ConsiderForwardJoin(
	ctx context.Context,
	aa daddr.AddressAttestation,
	chain dcert.Chain,
) (dview.ForwardJoinDecision, error) {
	resp := make(chan dview.ForwardJoinDecision, 1)
	m.ConsiderForwardJoinCh <- ConsiderForwardJoinRequest{
		AA:    aa,
		Chain: chain,
		Resp:  resp,
	}

	return <-resp, nil
}

func (m *AsyncManagerMock) ConsiderNeighborRequest(
	ctx context.Context, p dview.ActivePeer,
) (bool, error) {
	resp := make(chan bool, 1)
	m.ConsiderNeighborRequestCh <- ConsiderNeighborRequest{
		P:    p,
		Resp: resp,
	}

	return <-resp, nil
}

func (m *AsyncManagerMock) AddActivePeer(
	ctx context.Context, p dview.ActivePeer,
) (*dview.ActivePeer, error) {
	resp := make(chan *dview.ActivePeer, 1)
	m.AddActivePeerCh <- AddActivePeerRequest{
		P:    p,
		Resp: resp,
	}

	return <-resp, nil
}

func (m *AsyncManagerMock) MakeOutboundShuffle(
	ctx context.Context,
) (dview.OutboundShuffle, error) {
	resp := make(chan dview.OutboundShuffle, 1)
	m.MakeOutboundShuffleCh <- MakeOutboundShuffleRequest{
		Resp: resp,
	}

	return <-resp, nil
}

func (m *AsyncManagerMock) MakeShuffleResponse(
	ctx context.Context, src dcert.Chain, entries []dview.ShuffleEntry,
) ([]dview.ShuffleEntry, error) {
	resp := make(chan []dview.ShuffleEntry, 1)
	m.MakeShuffleResponseCh <- MakeShuffleResponseRequest{
		Src:     src,
		Entries: entries,
		Resp:    resp,
	}

	return <-resp, nil
}

func (m *AsyncManagerMock) HandleShuffleResponse(
	ctx context.Context, src dcert.Chain, entries []dview.ShuffleEntry,
) error {
	resp := make(chan struct{}, 1)
	m.HandleShuffleResponseCh <- HandleShuffleResponseRequest{
		Src:     src,
		Entries: entries,
		Resp:    resp,
	}
	return nil
}

func (m *AsyncManagerMock) RemoveActivePeer(
	ctx context.Context, p dview.ActivePeer,
) {
	// No side channel for this one, at least not yet.
	delete(m.PassivePeers, string(p.Chain.Root.RawSubjectPublicKeyInfo))
}

func (m *AsyncManagerMock) NActivePeers() int {
	return len(m.ActivePeers)
}

func (m *AsyncManagerMock) NPassivePeers() int {
	return len(m.PassivePeers)
}

type ConsiderJoinRequest struct {
	P    dview.ActivePeer
	Resp chan dview.JoinDecision
}

type ConsiderForwardJoinRequest struct {
	AA    daddr.AddressAttestation
	Chain dcert.Chain
	Resp  chan dview.ForwardJoinDecision
}

type ConsiderNeighborRequest struct {
	P    dview.ActivePeer
	Resp chan bool
}

type AddActivePeerRequest struct {
	P    dview.ActivePeer
	Resp chan *dview.ActivePeer
}

type MakeOutboundShuffleRequest struct {
	Resp chan dview.OutboundShuffle
}

type MakeShuffleResponseRequest struct {
	Src     dcert.Chain
	Entries []dview.ShuffleEntry
	Resp    chan []dview.ShuffleEntry
}

type HandleShuffleResponseRequest struct {
	Src     dcert.Chain
	Entries []dview.ShuffleEntry
	Resp    chan struct{}
}
