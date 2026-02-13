package dquic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/quic-go/quic-go"
)

// Dialer handles establishing QUIC connections with remote peers.
type Dialer struct {
	BaseTLSConf *tls.Config

	QUICTransport *quic.Transport
	QUICConfig    *quic.Config

	CAPool *dcert.Pool
}

// DialResult is the return type for [Dialer.Dial].
type DialResult struct {
	Conn Conn

	// A channel that is closed when the peer's CA certificate
	// is removed from the trusted CA pool.
	NotifyCARemoved <-chan struct{}
}

// Dial opens a QUIC connection to the given address,
// using appropriate TLS configuration that respects the current d.CAPool.
//
// The returned dial result includes a NotifyCARemoved channel
// which is closed if the remote's CA is removed from the trusted pool.
// It is the caller's responsibility to handle closing the returned connection
// upon detecting that the NotifyCARemoved channel is closed.
func (d Dialer) Dial(ctx context.Context, addr net.Addr) (DialResult, error) {
	tlsConf := d.BaseTLSConf.Clone()
	tlsConf.RootCAs = d.CAPool.CertPool()

	rawQC, err := d.QUICTransport.Dial(ctx, addr, tlsConf, d.QUICConfig)
	if err != nil {
		return DialResult{}, fmt.Errorf("failed to dial desired neighbor: %w", err)
	}

	qc := WrapConn(rawQC)

	// Now that we have a raw connection to that peer,
	// we need to ensure that we close it if that certificate is removed.
	vcs := qc.TLSConnectionState().VerifiedChains
	if len(vcs) == 0 {
		panic(fmt.Errorf(
			"IMPOSSIBLE: no verified chains after dialing remote host %q",
			addr,
		))
	}
	if len(vcs) > 1 {
		panic(fmt.Errorf(
			"TODO: handle multiple verified chains; dialing %q resulted in chains: %#v",
			addr, vcs,
		))
	}

	vc := vcs[0]
	ca := vc[len(vc)-1]

	notify := d.CAPool.NotifyRemoval(ca)
	if notify == nil {
		panic(errors.New(
			"BUG: failed to get notify removal channel after successful connection to peer",
		))
	}

	// For now, we have no external synchronization on this goroutine.
	// The goroutine is coupled to the lifecycle of the connection,
	// and it does not log or interact with anything other than the connection.
	// If it turns out this causes any data races,
	// then the Dialer will need an associated wait group.
	go closeConnOnCARemoved(qc, notify)

	return DialResult{
		Conn: qc,

		NotifyCARemoved: notify,
	}, nil
}

func closeConnOnCARemoved(qc Conn, notify <-chan struct{}) {
	select {
	case <-qc.Context().Done():
		return
	case <-notify:
		_ = qc.CloseWithError(CARemoved, CARemovedMessage)
	}
}
