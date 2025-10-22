package wingspan_test

import (
	"context"
	"crypto/ed25519"
	"io"
	"testing"
	"time"

	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/gordian-engine/dragon/wingspan"
	"github.com/gordian-engine/dragon/wingspan/wingspantest"
	"github.com/gordian-engine/dragon/wingspan/wspacket"
	"github.com/gordian-engine/dragon/wingspan/wspacket/wspackettest"
	"github.com/stretchr/testify/require"
)

func TestProtocol_outboundConnection(t *testing.T) {
	t.Run("from an existing connection", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		fx := wingspantest.NewProtocolFixture[
			wspackettest.Ed25519PacketIn, wspackettest.Ed25519PacketOut,
			wspackettest.Ed25519Delta, wspackettest.Ed25519Delta,
		](
			t, ctx,
			wingspantest.ProtocolFixtureConfig{
				Nodes: 2,

				ProtocolID:      0xd0,
				SessionIDLength: 3,
			},
		)
		defer cancel()

		// Node 0 will start the session first.
		c0, c1 := fx.ListenerSet.Dial(t, 0, 1)
		fx.AddConnection(c0, 0, 1)
		fx.AddConnection(c1, 1, 0)

		// We don't have a way to synchronize on the protocol
		// observing the connection change,
		// so instead just do a short sleep.
		timeoutCh := time.After(4 * time.Millisecond)

		pub0, _, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		pub1, _, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		_ = <-timeoutCh

		signContent := []byte(t.Name())
		s, m := wspackettest.NewEd25519State(ctx, signContent, []ed25519.PublicKey{pub0, pub1})
		sess0, err := fx.Protocols[0].NewSession(
			ctx, []byte("sid"), []byte("application hello"),
			s, m,
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

		fx := wingspantest.NewProtocolFixture[
			wspackettest.Ed25519PacketIn, wspackettest.Ed25519PacketOut,
			wspackettest.Ed25519Delta, wspackettest.Ed25519Delta,
		](
			t, ctx,
			wingspantest.ProtocolFixtureConfig{
				Nodes: 2,

				ProtocolID:      0xd0,
				SessionIDLength: 3,
			},
		)
		defer cancel()

		pub0, _, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		pub1, _, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		// Make the session before doing any dialing.
		signContent := []byte(t.Name())
		s, m := wspackettest.NewEd25519State(ctx, signContent, []ed25519.PublicKey{pub0, pub1})
		sess0, err := fx.Protocols[0].NewSession(
			ctx, []byte("sid"), []byte("application hello"),
			s, m,
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

func TestProtocol_packetContent(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fx := wingspantest.NewProtocolFixture[
		wspackettest.Ed25519PacketIn, wspackettest.Ed25519PacketOut,
		wspackettest.Ed25519Delta, wspackettest.Ed25519Delta,
	](
		t, ctx,
		wingspantest.ProtocolFixtureConfig{
			Nodes: 2,

			ProtocolID:      0xd0,
			SessionIDLength: 3,
		},
	)
	defer cancel()

	signContent := []byte("content to sign")

	pub0, priv0, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	pub1, priv1, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	allowedKeys := []ed25519.PublicKey{pub0, pub1}

	// Make a session on both sides before dialing.
	// Normally the application would be concerned with
	// how each side is aware of the sign content and allowed keys.
	state0, m0 := wspackettest.NewEd25519State(
		ctx, signContent, allowedKeys,
	)
	state1, m1 := wspackettest.NewEd25519State(
		ctx, signContent, allowedKeys,
	)
	defer state0.Wait()
	defer state1.Wait()
	defer cancel()

	sessID := []byte("sid")
	appHeader := []byte("ed25519 app hello")

	sess0, err := fx.Protocols[0].NewSession(
		ctx, sessID, appHeader,
		state0, m0,
	)
	require.NoError(t, err)
	defer sess0.Cancel()

	sess1, err := fx.Protocols[1].NewSession(
		ctx, sessID, appHeader,
		state1, m1,
	)
	require.NoError(t, err)
	defer sess0.Cancel()

	// Now connect the two nodes.
	c0, c1 := fx.ListenerSet.Dial(t, 0, 1)
	fx.AddConnection(c0, 0, 1)
	fx.AddConnection(c1, 1, 0)

	// Both sides need to accept the complementing stream.
	acceptCtx, acceptCancel := context.WithTimeout(ctx, time.Second)
	defer acceptCancel()

	s01 := testStreamHeaders(
		t, acceptCtx,
		c1, fx.Protocols[1],
		sessID, appHeader,
	)
	require.NoError(
		t,
		sess1.AcceptStream(
			ctx,
			dconn.Conn{
				QUIC:  c0,
				Chain: fx.ListenerSet.Leaves[0].Chain,
			},
			s01,
		),
	)

	s10 := testStreamHeaders(
		t, acceptCtx,
		c0, fx.Protocols[0],
		sessID, appHeader,
	)
	require.NoError(
		t,
		sess0.AcceptStream(
			ctx,
			dconn.Conn{
				QUIC:  c1,
				Chain: fx.ListenerSet.Leaves[1].Chain,
			},
			s10,
		),
	)
	acceptCancel()

	// First make a valid signature for zero,
	// and add it to the zero state.
	sig0 := ed25519.Sign(priv0, signContent)

	d0 := wspackettest.Ed25519Delta{
		PubKey: pub0,
		Sig:    sig0,
	}
	require.NoError(t, state0.UpdateFromPeer(ctx, d0))

	// Stream 0 should have been updated.
	_ = dtest.ReceiveSoon(t, m0.Ready)
	require.Equal(t, d0, m0.Val)
	m0 = m0.Next

	// And if everything was wired correctly, sess0 sent that packet to sess1,
	// which caused the m1 stream to update.
	_ = dtest.ReceiveSoon(t, m1.Ready)
	require.Equal(t, d0, m1.Val)
	m1 = m1.Next

	// And now if a signature originates from sess1, it reaches sess0.
	sig1 := ed25519.Sign(priv1, signContent)
	d1 := wspackettest.Ed25519Delta{
		PubKey: pub1,
		Sig:    sig1,
	}
	require.NoError(t, state1.UpdateFromPeer(ctx, d1))

	_ = dtest.ReceiveSoon(t, m1.Ready)
	require.Equal(t, d1, m1.Val)
	m1 = m1.Next

	_ = dtest.ReceiveSoon(t, m0.Ready)
	require.Equal(t, d1, m0.Val)
	m0 = m0.Next
}

func testStreamHeaders[
	PktIn any, PktOut wspacket.OutboundPacket,
	DeltaIn, DeltaOut any,
](
	t *testing.T,
	ctx context.Context,
	conn dquic.Conn,
	p *wingspan.Protocol[PktIn, PktOut, DeltaIn, DeltaOut],
	expSessionID, expAppHeader []byte,
) dquic.ReceiveStream {
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

	return rs1
}
