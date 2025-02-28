package dragon_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand/v2"
	"net"
	"testing"
	"time"

	"github.com/gordian-engine/dragon"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dragontest"
	"github.com/gordian-engine/dragon/dview"
	"github.com/gordian-engine/dragon/dview/dviewrand"
	"github.com/gordian-engine/dragon/dview/dviewtest"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestNewNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
	require.NoError(t, err)

	leaf, err := ca.CreateLeafCert(dcerttest.LeafConfig{
		DNSNames: []string{"localhost"},
	})
	require.NoError(t, err)

	tc := tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{leaf.Cert.Raw},
				PrivateKey:  leaf.PrivKey,
				Leaf:        leaf.Cert,
			},
		},

		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	uc, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	require.NoError(t, err)
	defer uc.Close()

	log := dtest.NewLogger(t)
	n, err := dragon.NewNode(ctx, log, dragon.NodeConfig{
		UDPConn: uc,
		QUIC:    dragon.DefaultQUICConfig(),
		TLS:     &tc,

		AdvertiseAddr: uc.LocalAddr().String(),

		ViewManager:   dviewtest.DenyingManager{},
		ShuffleSignal: make(chan struct{}),

		NewConnections: make(chan dconn.Conn, 8),
	})

	require.NoError(t, err)
	require.NotNil(t, n)

	defer n.Wait()
	defer cancel()
}

func TestNode_DialAndJoin_unrecognizedCert(t *testing.T) {
	t.Run("neither client nor server know each other", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		nw := dragontest.NewDefaultNetwork(t, ctx, dcerttest.FastConfig(), dcerttest.FastConfig())
		defer nw.Wait()
		defer cancel()

		out := dragontest.NewDefaultNetwork(t, ctx, dcerttest.FastConfig())
		defer out.Wait()
		defer cancel()

		require.Error(t, out.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[0].UDP.LocalAddr()))
	})

	t.Run("one-way knowledge", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfg1, cfg2 := dcerttest.FastConfig(), dcerttest.FastConfig()
		nw12 := dragontest.NewDefaultNetwork(t, ctx, cfg1, cfg2)
		defer nw12.Wait()
		defer cancel()

		nw123 := dragontest.NewDefaultNetwork(t, ctx, cfg1, cfg2, dcerttest.FastConfig())
		defer nw123.Wait()
		defer cancel()

		t.Run("client knows server, but server does not know client", func(t *testing.T) {
			require.Error(t, nw123.Nodes[2].Node.DialAndJoin(ctx, nw12.Nodes[1].UDP.LocalAddr()))
		})

		t.Run("server knows client, but client does not know server", func(t *testing.T) {
			require.Error(t, nw12.Nodes[1].Node.DialAndJoin(ctx, nw123.Nodes[2].UDP.LocalAddr()))
		})
	})
}

func TestNode_DialAndJoin_deny(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nw := dragontest.NewNetwork(
		t, ctx,
		[]dcerttest.CAConfig{dcerttest.FastConfig(), dcerttest.FastConfig()},
		func(_ int, c dragontest.NodeConfig) dragon.NodeConfig {
			out := c.ToDragonNodeConfig()

			// Explicitly deny any join requests.
			out.ViewManager = dviewtest.DenyingManager{}

			return out
		},
	)
	defer nw.Wait()
	defer cancel()

	// No active views before join.
	require.Zero(t, nw.Nodes[0].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[1].Node.ActiveViewSize())

	// TLS should work but the request should be denied.
	// TODO: it would be better to do a more specific error assertion here.
	require.Error(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// And no active views were added.
	require.Zero(t, nw.Nodes[0].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[1].Node.ActiveViewSize())
}

func TestNode_DialAndJoin_accept(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nw := dragontest.NewNetwork(
		t, ctx,
		[]dcerttest.CAConfig{dcerttest.FastConfig(), dcerttest.FastConfig()},
		func(_ int, c dragontest.NodeConfig) dragon.NodeConfig {
			out := c.ToDragonNodeConfig()

			// Explicitly accept join requests.
			out.ViewManager = dviewrand.New(
				dtest.NewLogger(t).With("node_sys", "view_manager"),
				dviewrand.Config{
					ActiveViewSize:  4,
					PassiveViewSize: 8,

					RNG: rand.New(rand.NewPCG(10, 20)), // Arbitrary fixed seed for this test.
				},
			)

			return out
		},
	)
	defer nw.Wait()
	defer cancel()

	// No active views before joining.
	require.Zero(t, nw.Nodes[0].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[1].Node.ActiveViewSize())

	require.NoError(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// Short delay to allow background work to happen on the join request.
	time.Sleep(50 * time.Millisecond)

	// Now both nodes report 1 active view member.
	require.Equal(t, 1, nw.Nodes[0].Node.ActiveViewSize())
	require.Equal(t, 1, nw.Nodes[1].Node.ActiveViewSize())
}

func TestNode_DialAndJoin_accept_intermediates(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nw := dragontest.NewNetwork(
		t, ctx,
		[]dcerttest.CAConfig{dcerttest.FastConfig(), dcerttest.FastConfig()},
		func(_ int, c dragontest.NodeConfig) dragon.NodeConfig {

			// Use the CA on the test node config,
			// to generate an intermediate CA,
			// and use that intermediate to generate a new leaf,
			// overriding the TLS config.
			i, err := c.CA.CreateIntermediate(dcerttest.FastConfig())
			require.NoError(t, err)

			leaf, err := i.CreateLeafCert(dcerttest.LeafConfig{
				DNSNames: []string{"localhost"},
			})

			c.TLS.Certificates = []tls.Certificate{
				{
					Certificate: [][]byte{leaf.Cert.Raw, i.Cert.Raw},
					PrivateKey:  leaf.PrivKey,

					Leaf: leaf.Cert,
				},
			}

			out := c.ToDragonNodeConfig()
			// Explicitly accept join requests.
			out.ViewManager = dviewrand.New(
				dtest.NewLogger(t).With("node_sys", "view_manager"),
				dviewrand.Config{
					ActiveViewSize:  4,
					PassiveViewSize: 8,

					RNG: rand.New(rand.NewPCG(10, 20)), // Arbitrary fixed seed for this test.
				},
			)

			return out
		},
	)
	defer nw.Wait()
	defer cancel()

	// No active views before joining.
	require.Zero(t, nw.Nodes[0].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[1].Node.ActiveViewSize())

	require.NoError(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// Short delay to allow background work to happen on the join request.
	time.Sleep(50 * time.Millisecond)

	// Now both nodes report 1 active view member.
	require.Equal(t, 1, nw.Nodes[0].Node.ActiveViewSize())
	require.Equal(t, 1, nw.Nodes[1].Node.ActiveViewSize())
}

func TestNode_forwardJoin(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nw := dragontest.NewNetwork(
		t, ctx,
		[]dcerttest.CAConfig{dcerttest.FastConfig(), dcerttest.FastConfig(), dcerttest.FastConfig()},
		func(_ int, c dragontest.NodeConfig) dragon.NodeConfig {
			out := c.ToDragonNodeConfig()

			// Explicitly accept join requests.
			out.ViewManager = dviewrand.New(
				dtest.NewLogger(t).With("node_sys", "view_manager"),
				dviewrand.Config{
					ActiveViewSize:  4,
					PassiveViewSize: 8,

					RNG: rand.New(rand.NewPCG(10, 20)), // Arbitrary fixed seed for this test.
				},
			)

			return out
		},
	)
	defer nw.Wait()
	defer cancel()

	// No active views before joining.
	require.Zero(t, nw.Nodes[0].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[1].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[2].Node.ActiveViewSize())

	// Node 0 joins Node 1 first.
	require.NoError(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// Short delay to allow background work to happen on the join request.
	time.Sleep(50 * time.Millisecond)

	// Now both nodes report 1 active view member.
	require.Equal(t, 1, nw.Nodes[0].Node.ActiveViewSize())
	require.Equal(t, 1, nw.Nodes[1].Node.ActiveViewSize())
	require.Zero(t, nw.Nodes[2].Node.ActiveViewSize())

	// Now, Node 2 also joins Node 1.
	// This causes Node 1 to send a forward join to Node 0.
	require.NoError(t, nw.Nodes[2].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// Another short delay for background work.
	time.Sleep(50 * time.Millisecond)

	require.Equal(t, 2, nw.Nodes[0].Node.ActiveViewSize())
	require.Equal(t, 2, nw.Nodes[1].Node.ActiveViewSize())
	require.Equal(t, 2, nw.Nodes[2].Node.ActiveViewSize())
}

func TestNode_shuffle(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Two mock view managers for this test,
	// so we can intercept messages for nodes 0 and 1.
	vm0 := dviewtest.NewAsyncManagerMock()
	vm1 := dviewtest.NewAsyncManagerMock()

	// We will override the shuffle signal for node 0.
	shuffleSig0 := make(chan struct{})

	origTrustedCAs := make([]*x509.Certificate, 2)

	nw := dragontest.NewNetwork(
		t, ctx,
		[]dcerttest.CAConfig{dcerttest.FastConfig(), dcerttest.FastConfig()},
		func(i int, c dragontest.NodeConfig) dragon.NodeConfig {
			out := c.ToDragonNodeConfig()
			switch i {
			case 0:
				out.ViewManager = vm0
				out.ShuffleSignal = shuffleSig0
				origTrustedCAs = out.InitialTrustedCAs
			case 1:
				out.ViewManager = vm1
			case 2, 3, 4, 5:
				// Still need to set a view manager.
				out.ViewManager = dviewtest.DenyingManager{}
			default:
				panic(fmt.Errorf("unexpected node index %d", i))
			}

			return out
		},
	)
	defer nw.Wait()
	defer cancel()

	// Four extra CAs so each of the two connected nodes
	// can shuffle two unknown nodes to the other.
	extraCAs := make([]*dcerttest.CA, 4)
	extraLeaves := make([]*dcerttest.LeafCert, 4)
	for i := range extraCAs {
		ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
		require.NoError(t, err)
		extraCAs[i] = ca

		l, err := ca.CreateLeafCert(dcerttest.LeafConfig{
			DNSNames: []string{
				fmt.Sprintf("extra-%d.example", i+2),
			},
		})
		extraLeaves[i] = l
	}

	// Both nodes should trust each other and the four extra CAs.
	for _, n := range nw.Nodes {
		n.Node.UpdateCAs([]*x509.Certificate{
			origTrustedCAs[0], origTrustedCAs[1],
			extraCAs[0].Cert, extraCAs[1].Cert, extraCAs[2].Cert, extraCAs[3].Cert,
		})
	}

	// First, vm1 has to consider the Join.
	// After that it can accept the peering.
	go func() {
		cjReq := <-vm1.ConsiderJoinCh
		cjReq.Resp <- dview.AcceptJoinDecision

		apReq := <-vm1.AddActivePeerCh
		apReq.Resp <- nil
	}()

	// Node 0 has to accept a peering eventually too.
	go func() {
		req := <-vm0.AddActivePeerCh
		req.Resp <- nil
	}()

	// Now begin the join.
	require.NoError(t, nw.Nodes[0].Node.DialAndJoin(ctx, nw.Nodes[1].UDP.LocalAddr()))

	// Next, we initiate a shuffle on zero.
	shuffleSig0 <- struct{}{}

	// That was synchronously accepted,
	// and now we can synchronously handle the outbound shuffle.
	shuffleEntriesFrom0 := make([]dview.ShuffleEntry, 2)
	for i := range shuffleEntriesFrom0 {
		aa, err := extraLeaves[i].AddressAttestation(
			fmt.Sprintf("extra-%d.example", i),
		)
		require.NoError(t, err)

		shuffleEntriesFrom0[i] = dview.ShuffleEntry{
			AA:    aa,
			Chain: extraLeaves[i].Chain,
		}
	}

	shufReq := <-vm0.MakeOutboundShuffleCh
	// Nothing to assert on shufReq.
	shufReq.Resp <- dview.OutboundShuffle{
		Dest:    nw.Chains[1],
		Entries: shuffleEntriesFrom0,
	}

	// Now since the outbound shuffle went out to chain 1,
	// vm1 needs to produce a shuffle response.

	shufRespReq := <-vm1.MakeShuffleResponseCh

	// Make sure the input to MakeShuffleResponse
	// matches what was sent in the initiated shuffle.
	require.Equal(t, nw.Chains[0], shufRespReq.Src)
	require.Equal(t, shuffleEntriesFrom0, shufRespReq.Entries)

	shuffleEntriesFrom1 := make([]dview.ShuffleEntry, 2)
	for i := range shuffleEntriesFrom1 {
		aa, err := extraLeaves[i+2].AddressAttestation(
			fmt.Sprintf("extra-%d.example", i+2),
		)
		require.NoError(t, err)

		shuffleEntriesFrom1[i] = dview.ShuffleEntry{
			AA:    aa,
			Chain: extraLeaves[i+2].Chain,
		}
	}
	shufRespReq.Resp <- shuffleEntriesFrom1

	// Now that 1 sent its response, 0 should handle the response.
	handleRespReq := <-vm0.HandleShuffleResponseCh
	require.Equal(t, nw.Chains[1], handleRespReq.Src)
	require.Equal(t, shuffleEntriesFrom1, handleRespReq.Entries)
	close(handleRespReq.Resp)

	// Allow some background work in case anything is going to panic here.
	time.Sleep(20 * time.Millisecond)
}
