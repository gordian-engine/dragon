package wspackettest

import (
	"context"
	"slices"
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
	t.Run("CentralState", func(t *testing.T) {
		t.Run("UpdateFromPeer returns ErrRedundantUpdate on duplicate call", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s, fx := f(t, ctx, 1)

			d := fx.GetDelta(0)

			require.NoError(t, s.UpdateFromPeer(ctx, d))
			require.ErrorIs(t, s.UpdateFromPeer(ctx, d), wspacket.ErrRedundantUpdate)
		})

		t.Run("stream for derived states get updated", func(t *testing.T) {
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
	})

	t.Run("InboundRemoteState", func(t *testing.T) {
		t.Run("CheckIncoming returns ErrDuplicateSentPacket", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s, fx := f(t, ctx, 1)

			i, _, err := s.NewInboundRemoteState(ctx)
			require.NoError(t, err)

			d := fx.GetDelta(0)
			require.NoError(t, i.CheckIncoming(d))

			require.ErrorIs(t, i.CheckIncoming(d), wspacket.ErrDuplicateSentPacket)
		})

		t.Run("CheckIncoming returns ErrAlreadyHavePacket", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s, fx := f(t, ctx, 1)

			i, _, err := s.NewInboundRemoteState(ctx)
			require.NoError(t, err)

			// Another peer sends the delta,
			// so we receive it from the central state first.
			d := fx.GetDelta(0)
			require.NoError(t, i.ApplyUpdateFromCentral(d))

			// Then later, this connected peer sends the same delta.
			require.ErrorIs(t, i.CheckIncoming(d), wspacket.ErrAlreadyHavePacket)
		})
	})

	t.Run("OutboundRemoteState", func(t *testing.T) {
		t.Run("UnsentPackets respects marking a packet sent", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s, fx := f(t, ctx, 2)

			o, _, err := s.NewOutboundRemoteState(ctx)
			require.NoError(t, err)

			// No unsent packets in initial state.
			require.Empty(t, slices.Collect(o.UnsentPackets()))

			d := fx.GetDelta(0)
			require.NoError(t, o.ApplyUpdateFromCentral(d))

			require.Len(t, slices.Collect(o.UnsentPackets()), 1)

			i := 0
			for u := range o.UnsentPackets() {
				u.MarkSent()
				if i > 0 {
					t.Fatal("expected only one unsent packet but got more")
				}
				i++
			}

			require.Empty(t, slices.Collect(o.UnsentPackets()))
		})

		t.Run("UnsentPackets respects AddUnverifiedFromPeer", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s, fx := f(t, ctx, 2)

			o, _, err := s.NewOutboundRemoteState(ctx)
			require.NoError(t, err)

			d := fx.GetDelta(0)

			// Adding an unverified delta
			// does not cause the delta to be treated as an unsent packet.
			require.NoError(t, o.AddUnverifiedFromPeer(d))
			require.Empty(t, slices.Collect(o.UnsentPackets()))

			// Now adding the same delta as an update from central
			// also does not treat the delta as an unsent packet.
			require.NoError(t, o.ApplyUpdateFromCentral(d))
			require.Empty(t, slices.Collect(o.UnsentPackets()))
		})
	})
}
