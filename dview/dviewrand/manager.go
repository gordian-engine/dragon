package dviewrand

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"

	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dview"
)

type Manager struct {
	log *slog.Logger

	rng *rand.Rand

	aLimit, pLimit int

	aByCAPKI map[string]*dview.ActivePeer
	pByCAPKI map[string]*dview.PassivePeer
}

type Config struct {
	// Target sizes for active and passive views.
	ActiveViewSize, PassiveViewSize int

	// We actually aren't using the RNG yet.
	// If it turns out we can get by solely on random map iteration,
	// then we should remove the RNG field.
	RNG *rand.Rand
}

func New(log *slog.Logger, cfg Config) *Manager {
	if cfg.ActiveViewSize <= 0 {
		panic(fmt.Errorf(
			"Config.ActiveViewSize must be positive (got %d)", cfg.ActiveViewSize,
		))
	}

	if cfg.PassiveViewSize <= 0 {
		panic(fmt.Errorf(
			"Config.PassiveViewSize must be positive (got %d)", cfg.PassiveViewSize,
		))
	}

	if cfg.RNG == nil {
		panic(errors.New("BUG: Config.RNG must not be nil"))
	}

	return &Manager{
		log: log,

		rng: cfg.RNG,

		aLimit: cfg.ActiveViewSize,
		pLimit: cfg.PassiveViewSize,

		// These are both +1 to account for bursting an additional peer.
		// They should only need +1 due to methods being called serially.
		aByCAPKI: make(map[string]*dview.ActivePeer, cfg.ActiveViewSize+1),
		pByCAPKI: make(map[string]*dview.PassivePeer, cfg.PassiveViewSize+1),
	}
}

// ConsiderJoin accepts the peer if there is no existing active peer
// from the same trusted CA.
func (m *Manager) ConsiderJoin(
	_ context.Context, p dview.ActivePeer,
) (dview.JoinDecision, error) {
	caCert := p.Chain.Root
	if _, ok := m.aByCAPKI[string(caCert.RawSubjectPublicKeyInfo)]; ok {
		// We already have an active peer from this CA.
		return dview.DisconnectAndForwardJoinDecision, nil
	}

	// Otherwise it's acceptable.
	return dview.AcceptJoinDecision, nil
}

// ConsiderNeighborRequest accepts the request
// if there is no existing active peer from the same trusted CA.
func (m *Manager) ConsiderNeighborRequest(
	_ context.Context, p dview.ActivePeer,
) (bool, error) {
	caCert := p.Chain.Root
	_, have := m.aByCAPKI[string(caCert.RawSubjectPublicKeyInfo)]

	// Acceptable if we don't already have an active peer from this CA.
	return !have, nil
}

// ConsiderForwardJoin always continues forwarding,
// and it wants to connect to the new neighbor
// if we don't already have one from the same CA.
func (m *Manager) ConsiderForwardJoin(
	_ context.Context, aa daddr.AddressAttestation, chain dcert.Chain,
) (dview.ForwardJoinDecision, error) {
	_, alreadyHaveCA := m.aByCAPKI[string(chain.Root.RawSubjectPublicKeyInfo)]

	return dview.ForwardJoinDecision{
		ContinueForwarding:  true,
		MakeNeighborRequest: !alreadyHaveCA,
	}, nil
}

func (m *Manager) AddPeering(
	_ context.Context, p dview.ActivePeer,
) (evicted *dview.ActivePeer, err error) {
	// Make sure we don't have an active peer with the same CA.
	caCert := p.Chain.Root
	if _, ok := m.aByCAPKI[string(caCert.RawSubjectPublicKeyInfo)]; ok {
		// We already have an active peer from this CA.
		return nil, dview.ErrAlreadyActiveCA
	}

	// We don't have an active peer, so we can afford it.
	// If we are under the active limit, we need to pick a peer to evict, though.
	var deleteActiveKey string
	if len(m.aByCAPKI) == m.aLimit {
		deleteActiveKey, evicted = m.randomActivePeer()
	}

	m.aByCAPKI[string(caCert.RawSubjectPublicKeyInfo)] = &p
	delete(m.aByCAPKI, deleteActiveKey)

	// We can just attempt to delete the passive peer if one exists,
	// without doing a lookup first.
	delete(m.pByCAPKI, string(caCert.RawSubjectPublicKeyInfo))
	return evicted, nil
}

func (m *Manager) RemoveActivePeer(_ context.Context, p dview.ActivePeer) {
	caCert := p.Chain.Root
	if _, ok := m.aByCAPKI[string(caCert.RawSubjectPublicKeyInfo)]; !ok {
		// Wasn't in the active set.
		// We'll panic here for now at least.
		// Seems like the kernel should prevent this from happening.
		panic(fmt.Errorf(
			"BUG: attempted to remove active peer who was not in the active set",
		))
	}

	delete(m.aByCAPKI, string(caCert.RawSubjectPublicKeyInfo))
}

func (m *Manager) randomActivePeer() (string, *dview.ActivePeer) {
	// First entry by random map iteration.
	// TODO: use RNG to actually skip a random count.
	for k, p := range m.aByCAPKI {
		return k, p
	}

	// Map was empty.
	return "", nil
}

func (m *Manager) randomPassivePeer() (string, *dview.PassivePeer) {
	// First entry by random map iteration.
	// TODO: use RNG to actually skip a random count.
	for k, p := range m.pByCAPKI {
		return k, p
	}

	// Map was empty.
	return "", nil
}

func (m *Manager) MakeOutboundShuffle(ctx context.Context) (dview.OutboundShuffle, error) {
	return dview.OutboundShuffle{}, errors.New("TODO")
}

func (m *Manager) NActivePeers() int {
	return len(m.aByCAPKI)
}

func (m *Manager) NPassivePeers() int {
	return len(m.pByCAPKI)
}
