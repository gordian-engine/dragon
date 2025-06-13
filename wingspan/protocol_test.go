package wingspan_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/wingspan"
	"github.com/gordian-engine/dragon/wingspan/wingspantest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestProtocol_outboundConnection(t *testing.T) {
	t.Run("from an existing connection", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		fx := wingspantest.NewProtocolFixture(t, ctx, wingspantest.ProtocolFixtureConfig{
			Nodes: 2,

			ProtocolID:      0xd0,
			SessionIDLength: 3,
		})
		defer cancel()

		// Node 0 will start the session first.
		c0, c1 := fx.ListenerSet.Dial(t, 0, 1)
		fx.AddConnection(c0, 0, 1)
		fx.AddConnection(c1, 1, 0)

		// We don't have a way to synchronize on the protocol
		// observing the connection change,
		// so instead just do a short sleep.
		time.Sleep(4 * time.Millisecond)

		sess0, err := fx.Protocols[0].NewSession(
			ctx, []byte("sid"), []byte("application hello"),
		)
		require.NoError(t, err)

		// TODO: we don't yet have methods to write on the session,
		// and closing the session isn't meaningful yet either.
		_ = sess0

		// Now Node 1 should be able to accept a uni stream
		// and observe the expected header data.
		testStreamHeaders(
			t, ctx,
			c1, fx.Protocols[1],
			[]byte("sid"), []byte("application hello"),
		)
	})

	t.Run("from a new connection", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		fx := wingspantest.NewProtocolFixture(t, ctx, wingspantest.ProtocolFixtureConfig{
			Nodes: 2,

			ProtocolID:      0xd0,
			SessionIDLength: 3,
		})
		defer cancel()

		// Make the session before doing any dialing.
		sess0, err := fx.Protocols[0].NewSession(
			ctx, []byte("sid"), []byte("application hello"),
		)
		require.NoError(t, err)

		// TODO: we don't yet have methods to write on the session,
		// and closing the session isn't meaningful yet either.
		_ = sess0

		// Now join the nodes.
		c0, c1 := fx.ListenerSet.Dial(t, 0, 1)
		fx.AddConnection(c0, 0, 1)
		fx.AddConnection(c1, 1, 0)

		// Now Node 1 should be able to accept a uni stream
		// and observe the expected header data.
		testStreamHeaders(
			t, ctx,
			c1, fx.Protocols[1],
			[]byte("sid"), []byte("application hello"),
		)
	})
}

func testStreamHeaders(
	t *testing.T,
	ctx context.Context,
	conn quic.Connection,
	p *wingspan.Protocol,
	expSessionID, expAppHeader []byte,
) {
	t.Helper()

	rs1, err := conn.AcceptUniStream(ctx)
	require.NoError(t, err)

	require.NoError(t, rs1.SetReadDeadline(time.Now().Add(100*time.Millisecond)))

	var buf [1]byte
	_, err = io.ReadFull(rs1, buf[:])
	require.NoError(t, err)
	require.Equal(t, byte(0xd0), buf[0])

	sid, err := p.ExtractStreamSessionID(rs1, nil)
	require.NoError(t, err)
	require.Equal(t, expSessionID, sid)

	ah, err := wingspan.ExtractStreamApplicationHeader(rs1, nil)
	require.NoError(t, err)
	require.Equal(t, expAppHeader, ah)
}
