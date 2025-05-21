package dpeerset_test

import (
	"context"
	"testing"

	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/internal/dpeerset"
	"github.com/gordian-engine/dragon/internal/dpeerset/dpeersettest"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
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

func TestActiveView_HasConnectionToAddress(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fx := dpeersettest.NewFixture(t)

	av := fx.NewActiveView(ctx)
	require.NotNil(t, av)
	defer av.Wait()
	defer cancel()

	// Make a fake peer.
	ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)
	leaf, err := ca.CreateLeafCert(dcerttest.LeafConfig{
		DNSNames: []string{"leaf.example"},
	})
	require.NoError(t, err)
	aa, err := leaf.AddressAttestation("leaf.example")
	require.NoError(t, err)

	connAddr := "192.168.2.1:12345"
	conn := &dquictest.StubConnection{
		RemoteAddrValue: dquictest.StubNetAddr{
			StringValue: connAddr,
		},
	}

	peer := dpeerset.Peer{
		Conn: conn,

		AA:    aa,
		Chain: leaf.Chain,

		Admission: dquictest.NewStubStream(ctx),
	}

	require.NoError(t, av.Add(ctx, peer))

	// Have to drain this channel for the later remove to complete,
	// as the connection changes are 1-buffered.
	_ = dtest.ReceiveSoon(t, fx.ConnectionChanges)

	// We report a connection on the address reported by the underlying connection.
	has, err := av.HasConnectionToAddress(ctx, connAddr)
	require.NoError(t, err)
	require.True(t, has)

	// We do not attempt to match DNS names.
	has, err = av.HasConnectionToAddress(ctx, "leaf.example:12345")
	require.NoError(t, err)
	require.False(t, has)

	// After removing the peer, we no longer report a connection.
	require.NoError(t, av.Remove(ctx, dpeerset.PeerCertIDFromChain(peer.Chain)))
	has, err = av.HasConnectionToAddress(ctx, connAddr)
	require.NoError(t, err)
	require.False(t, has)
}
