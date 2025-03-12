package dpeerset_test

import (
	"context"
	"testing"

	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/internal/dpeerset"
	"github.com/gordian-engine/dragon/internal/dpeerset/dpeersettest"
	"github.com/gordian-engine/dragon/internal/dquictest"
	"github.com/gordian-engine/dragon/internal/dquicwrap"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestActiveView_NewConnections(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fx := dpeersettest.NewFixture(t)

	av := fx.NewActiveView(ctx)
	require.NotNil(t, av)
	defer av.Wait()
	defer cancel()

	ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)
	leaf, err := ca.CreateLeafCert(dcerttest.LeafConfig{
		DNSNames: []string{"leaf.example"},
	})
	require.NoError(t, err)
	aa, err := leaf.AddressAttestation("leaf.example")
	require.NoError(t, err)

	conn := new(dquictest.StubConnection)

	peer := dpeerset.Peer{
		Conn: conn,

		AA:    aa,
		Chain: leaf.Chain,

		Admission: dquictest.NewStubStream(ctx),
	}

	require.NoError(t, av.Add(ctx, peer))

	cc := dtest.ReceiveSoon(t, fx.ConnectionChanges)

	// We can't use simple equality since the connection we received
	// is wrapped -- the connections exposed to the application layer
	// have some restrictions not present on plain quic.Connections.
	wrappedConn := cc.Conn.QUIC.(*dquicwrap.Conn)
	require.True(t, wrappedConn.WrapsConnection(conn))
	require.True(t, cc.Adding)

	require.Equal(t, leaf.Chain, cc.Conn.Chain)

	require.NoError(t, av.Remove(ctx, dpeerset.PeerCertIDFromChain(peer.Chain)))

	cc = dtest.ReceiveSoon(t, fx.ConnectionChanges)

	wrappedConn = cc.Conn.QUIC.(*dquicwrap.Conn)
	require.True(t, wrappedConn.WrapsConnection(conn))
	require.False(t, cc.Adding)
}
