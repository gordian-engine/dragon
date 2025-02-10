package dragon_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"dragon.example/dragon"
	"dragon.example/dragon/dca/dcatest"
	"dragon.example/dragon/internal/dtest"
	"github.com/stretchr/testify/require"
)

func TestNewNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca, err := dcatest.GenerateCA(dcatest.FastConfig())
	require.NoError(t, err)

	leaf, err := ca.CreateLeafCert(dcatest.LeafConfig{
		DNSNames: []string{"localhost"},
	})
	require.NoError(t, err)

	tc := tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{leaf.Cert.Raw},
				PrivateKey:  leaf.PrivKey,
			},
		},
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
	})

	require.NoError(t, err)
	require.NotNil(t, n)

	defer n.Wait()
	defer cancel()
}

func TestNodeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := dtest.NewLogger(t)

	tp, err := dcatest.NewTrustPool(dcatest.FastConfig(), dcatest.FastConfig())
	require.NoError(t, err)

	uc0, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	require.NoError(t, err)
	defer uc0.Close()

	leaf0, err := tp.CAs[0].CreateLeafCert(dcatest.LeafConfig{
		DNSNames: []string{"localhost"},
	})
	require.NoError(t, err)

	tc0 := tls.Config{
		// The certificates we present.
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{leaf0.Cert.Raw},
				PrivateKey:  leaf0.PrivKey,
			},
		},

		RootCAs: tp.Pool,
	}

	n0, err := dragon.NewNode(ctx, log.With("node", 0), dragon.NodeConfig{
		UDPConn: uc0,
		QUIC:    dragon.DefaultQUICConfig(),
		TLS:     &tc0,
	})

	require.NoError(t, err)
	require.NotNil(t, n0)

	defer n0.Wait()
	defer cancel()

	leaf1, err := tp.CAs[1].CreateLeafCert(dcatest.LeafConfig{
		DNSNames: []string{"localhost"},
	})
	require.NoError(t, err)

	tc1 := tls.Config{
		// The certificates we present.
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{leaf1.Cert.Raw},
				PrivateKey:  leaf1.PrivKey,
			},
		},

		RootCAs: tp.Pool,
	}
	uc1, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	require.NoError(t, err)
	defer uc1.Close()

	n1, err := dragon.NewNode(ctx, log.With("node", 1), dragon.NodeConfig{
		UDPConn: uc1,
		QUIC:    dragon.DefaultQUICConfig(),
		TLS:     &tc1,
	})

	require.NoError(t, err)
	require.NotNil(t, n1)

	defer n1.Wait()
	defer cancel()

	conn, err := n0.DialPeer(ctx, uc1.LocalAddr())
	require.NoError(t, err)

	require.NoError(t, conn.SendDatagram([]byte("hello")))

	// Delay ending the test function so that the background goroutines
	// have time to process messages.
	time.Sleep(50 * time.Millisecond)
}
