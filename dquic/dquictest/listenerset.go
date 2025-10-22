package dquictest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dcert/dcerttest"
	"github.com/gordian-engine/dragon/dquic"
	"github.com/gordian-engine/dragon/internal/dtest"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// ListenerSet is a collection of QUIC listeners,
// who mutually trust each others' CA certificates.
// They are capable of dialing one another.
type ListenerSet struct {
	Pool *dcert.Pool

	CAs    []*dcerttest.CA
	Leaves []*dcerttest.LeafCert

	UDPConns []*net.UDPConn

	TLSConfigs []*tls.Config

	QTs []*quic.Transport
	QLs []*quic.Listener
}

// NewListenerSet initializes a new ListenerSet,
// with count number of listeners.
// There are no active connections;
// use [*ListenerSet.Dialer] to make a dialer and dial another peer.
//
// The UDP connections are closed as part of [*testing.T.Cleanup].
func NewListenerSet(t *testing.T, ctx context.Context, count int) *ListenerSet {
	t.Helper()

	pool := dcert.NewPool()

	ls := &ListenerSet{
		Pool: pool,

		CAs:    make([]*dcerttest.CA, count),
		Leaves: make([]*dcerttest.LeafCert, count),

		UDPConns: make([]*net.UDPConn, count),

		TLSConfigs: make([]*tls.Config, count),

		QTs: make([]*quic.Transport, count),
		QLs: make([]*quic.Listener, count),
	}

	t.Cleanup(func() {
		for _, uc := range ls.UDPConns {
			if uc != nil {
				uc.Close()
			}
		}
	})

	for i := range count {
		ca, err := dcerttest.GenerateCA(dcerttest.FastConfig())
		require.NoError(t, err)

		leafCert, err := ca.CreateLeafCert(dcerttest.LeafConfig{
			DNSNames: []string{
				fmt.Sprintf("leaf%02d.example.com", i),
			},
		})
		require.NoError(t, err)

		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
			IP: net.IPv4(127, 0, 0, 1),
		})
		require.NoError(t, err)

		qt := dquic.MakeTransport(ctx, udpConn)

		tlsConf := &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{leafCert.Cert.Raw},
					PrivateKey:  leafCert.PrivKey,

					Leaf: leafCert.Cert,
				},
			},

			ClientAuth: tls.RequireAndVerifyClientCert,
		}
		ql, err := dquic.StartListener(tlsConf, pool, dquic.DefaultConfig(), qt)
		require.NoError(t, err)

		ls.CAs[i] = ca
		ls.Leaves[i] = leafCert

		ls.UDPConns[i] = udpConn

		ls.TLSConfigs[i] = tlsConf

		ls.QTs[i] = qt
		ls.QLs[i] = ql

		pool.AddCA(ca.Cert)
	}

	return ls
}

// Dial dials from the connection at srcIdx, to the listener at dstIdx.
// It returns srcConn, which is the outgoing connection from the source,
// and dstConn, which is the inbound connection for the destination.
//
// To do this, the listener set temporarily
// accepts a connection on the destination listener.
// If there is already an attempt to accept a connection there,
// the two attempts will race and the test will be inconsistent.
func (ls *ListenerSet) Dial(t *testing.T, srcIdx, dstIdx int) (srcConn, dstConn dquic.Conn) {
	t.Helper()

	if srcIdx < 0 || srcIdx >= len(ls.UDPConns) || dstIdx < 0 || dstIdx >= len(ls.UDPConns) {
		t.Fatalf(
			"indices must be in range [0, %d]; got srcIdx=%d and dstIdx=%d",
			len(ls.UDPConns)-1, srcIdx, dstIdx,
		)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(cancel)

	connAcceptedCh := make(chan *quic.Conn, 1)

	go func() {
		acceptedConn, err := ls.QLs[dstIdx].Accept(ctx)
		if err != nil {
			t.Error(err)
			connAcceptedCh <- nil
			return
		}

		connAcceptedCh <- acceptedConn
	}()

	res, err := ls.Dialer(srcIdx).Dial(ctx, ls.UDPConns[dstIdx].LocalAddr())
	require.NoError(t, err)

	acceptedConn := dtest.ReceiveSoon(t, connAcceptedCh)
	require.NotNil(t, acceptedConn)

	return res.Conn, dquic.WrapConn(acceptedConn)
}

func (ls *ListenerSet) Dialer(idx int) dquic.Dialer {
	return dquic.Dialer{
		BaseTLSConf: ls.TLSConfigs[idx],

		QUICTransport: ls.QTs[idx],

		// Currently always using the default config when creating the set anyway.
		QUICConfig: dquic.DefaultConfig(),

		CAPool: ls.Pool,
	}
}
