package breathcast_test

import (
	"context"
	"testing"

	"github.com/gordian-engine/dragon/breathcast"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dquic/dquictest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestProtocol_Originate_header(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := dtest.NewLogger(t)
	connChanges := make(chan dconn.Change)
	p := breathcast.NewProtocol(ctx, log, breathcast.ProtocolConfig{
		ConnectionChanges: connChanges,
	})

	defer p.Wait()
	defer cancel()

	// Chain for the stub connection.
	ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)
	leafCert, err := ca.CreateLeafCert(dcerttest.LeafConfig{
		DNSNames: []string{"leaf.example.com"},
	})
	require.NoError(t, err)

	// Add the connection to the protocol.
	conn := &dquictest.StubConnection{
		// Does this need a modified ConnectionState with certirficates?
	}
	dtest.SendSoon(t, connChanges, dconn.Change{
		Conn: dconn.Conn{
			QUIC:  conn,
			Chain: leafCert.Chain,
		},
		Adding: true,
	})

	// Now the application chooses to Originate.
	header := []byte("dummy header")

	dataChunks := [][]byte{
		[]byte("data0"),
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
	}

	parityChunks := [][]byte{
		[]byte("parity0"),
	}

	_ = p.Originate(ctx, header, dataChunks, parityChunks)

	// TODO: assert that the header is sent to the peer.
	// A lower level QUIC connection pair might actually
	// be easier than using stubs for this.
}
