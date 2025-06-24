package wspackettest

import (
	"context"
	"testing"

	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
	"github.com/stretchr/testify/require"
)

// StateFixtureFunc returns a state instance and a delta creator.
// The testing.T instance is available if needed,
// for instance to register a t.Cleanup after context cancellation.
// The context is guaranteed to be canceled before the test completes.
type StateFixtureFunc[D any] func(t *testing.T, ctx context.Context, nDeltas int) (
	wspacket.CentralState[D], StateFixture[D],
)

type StateFixture[D any] interface {
	// DeltaCreatorFunc returns a valid delta at the given index.
	// Implementations should panic for n < 0 or n >= nDeltas.
	GetDelta(n int) D

	// Get a delta that will cause a call to [wspacket.CentralState.UpdateFromPeer]
	// to fail with an application-specific error.
	GetInvalidDelta() D
}

// TestStateCompliance runs compliance tests
// for a [wspacket.CentralState] implementation.
func TestStateCompliance[D any](t *testing.T, f StateFixtureFunc[D]) {
	t.Run("UpdateFromPeer returns ErrRedundantUpdate on duplicate call", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		s, fx := f(t, ctx, 1)

		d := fx.GetDelta(0)

		require.NoError(t, s.UpdateFromPeer(ctx, d))
		require.ErrorIs(t, s.UpdateFromPeer(ctx, d), wspacket.ErrRedundantUpdate)
	})

	t.Run("multicasts for derived states get updated", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		s, fx := f(t, ctx, 1)

		d := fx.GetDelta(0)

		_, mo, err := s.NewOutboundRemoteState(ctx)
		require.NoError(t, err)

		_, mi, err := s.NewInboundRemoteState(ctx)
		require.NoError(t, err)

		s.UpdateFromPeer(ctx, d)

		dtest.ReceiveSoon(t, mo.Ready)
		dtest.ReceiveSoon(t, mi.Ready)
	})
}
