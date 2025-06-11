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

// Manager is a randomness-based [dview.Manager],
// closely following the behavior specified in the HyParView whitepaper.
type Manager struct {
	log *slog.Logger

	rng *rand.Rand

	aLimit, pLimit int

	aByCA map[dcert.CACertHandle]*dview.ActivePeer
	pByCA map[dcert.CACertHandle]*dview.PassivePeer
}

type Config struct {
	// Target sizes for active and passive views.
	ActiveViewSize, PassiveViewSize int

	// The RNG is used for randomness in decisions.
	RNG *rand.Rand
}

// New returns a new Manager.
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
		aByCA: make(map[dcert.CACertHandle]*dview.ActivePeer, cfg.ActiveViewSize+1),
		pByCA: make(map[dcert.CACertHandle]*dview.PassivePeer, cfg.PassiveViewSize+1),
	}
}

// ConsiderJoin accepts the peer if there is no existing active peer
// from the same trusted CA.
func (m *Manager) ConsiderJoin(
	_ context.Context, p dview.ActivePeer,
) (dview.JoinDecision, error) {
	if _, ok := m.aByCA[p.Chain.RootHandle]; ok {
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
	_, have := m.aByCA[p.Chain.RootHandle]

	// Acceptable if we don't already have an active peer from this CA.
	return !have, nil
}

// ConsiderForwardJoin always continues forwarding,
// and it wants to connect to the new neighbor
// if we don't already have one from the same CA.
func (m *Manager) ConsiderForwardJoin(
	_ context.Context, aa daddr.AddressAttestation, chain dcert.Chain,
) (dview.ForwardJoinDecision, error) {
	_, alreadyHaveCA := m.aByCA[chain.RootHandle]

	return dview.ForwardJoinDecision{
		ContinueForwarding:  true,
		MakeNeighborRequest: !alreadyHaveCA,
	}, nil
}

func (m *Manager) AddActivePeer(
	_ context.Context, p dview.ActivePeer,
) (evicted *dview.ActivePeer, err error) {
	// Make sure we don't have an active peer with the same CA.
	if _, ok := m.aByCA[p.Chain.RootHandle]; ok {
		// We already have an active peer from this CA.
		return nil, dview.ErrAlreadyActiveCA
	}

	// We don't have an active peer with the same CA,
	// so we can afford to add it.
	// If we are under the active limit, we need to pick a peer to evict, though.
	var deleteActiveKey dcert.CACertHandle
	if len(m.aByCA) >= m.aLimit {
		deleteActiveKey, evicted = m.randomActivePeer()
	}

	m.aByCA[p.Chain.RootHandle] = &p
	delete(m.aByCA, deleteActiveKey)

	// We can just attempt to delete the passive peer if one exists,
	// without doing a lookup first.
	delete(m.pByCA, p.Chain.RootHandle)
	return evicted, nil
}

func (m *Manager) RemoveActivePeer(_ context.Context, p dview.ActivePeer) {
	if _, ok := m.aByCA[p.Chain.RootHandle]; !ok {
		// Wasn't in the active set.
		// We'll panic here for now at least.
		// Seems like the kernel should prevent this from happening.
		panic(fmt.Errorf(
			"BUG: attempted to remove active peer who was not in the active set",
		))
	}

	delete(m.aByCA, p.Chain.RootHandle)
}

func (m *Manager) randomActivePeer() (dcert.CACertHandle, *dview.ActivePeer) {
	// Map iteration order simply is unspecified, not random,
	// so use the RNG to pick.
	more := m.rng.IntN(len(m.aByCA))
	for k, p := range m.aByCA {
		if more == 0 {
			return k, p
		}
		more--
	}

	// Map was empty.
	return dcert.CACertHandle{}, nil
}

func (m *Manager) randomPassivePeer() (dcert.CACertHandle, *dview.PassivePeer) {
	// Map iteration order simply is unspecified, not random,
	// so use the RNG to pick.
	more := m.rng.IntN(len(m.aByCA))
	for k, p := range m.pByCA {
		if more == 0 {
			return k, p
		}
		more--
	}

	// Map was empty.
	return dcert.CACertHandle{}, nil
}

func (m *Manager) MakeOutboundShuffle(ctx context.Context) (dview.OutboundShuffle, error) {
	return dview.OutboundShuffle{}, errors.New("TODO")
}

func (m *Manager) MakeShuffleResponse(
	ctx context.Context, src dcert.Chain, entries []dview.ShuffleEntry,
) ([]dview.ShuffleEntry, error) {
	return nil, errors.New("TODO")
}

func (m *Manager) HandleShuffleResponse(
	ctx context.Context, src dcert.Chain, entries []dview.ShuffleEntry,
) error {
	return errors.New("TODO")
}

func (m *Manager) NActivePeers() int {
	return len(m.aByCA)
}

func (m *Manager) NPassivePeers() int {
	return len(m.pByCA)
}
