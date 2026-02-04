package dquic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/gordian-engine/dragon/dcert"
	"github.com/quic-go/quic-go"
)

// MakeTransport returns a quic.Transport.
// The transport is used for finer conrol over connection behavior
// than a simple call to quic.Listen.
func MakeTransport(connContext context.Context, udpConn *net.UDPConn) *quic.Transport {
	return &quic.Transport{
		Conn: udpConn,

		// Skip: ConnectionIDLength: use default of 4 for now.
		// Skip: ConnectionIDGenerator: use default generation for now.

		// TODO: Provide this so that we can handle stateless resets,
		// to "quickly recover from crashes and reboots of this node".
		StatelessResetKey: nil,

		// Skip: tokenGeneratorKey: should not be necessary for a single server for one domain.

		// Skip: MaxTokenAge: use default of 24h for now.

		// Skip: DisableVersionNegotiationPackets: we probably want this enabled.

		// Skip: VerifySourceAddress: should probably just be on by default,
		// or maybe should use a rate limiter.
		// If we are relying on GeoIP lookup, then we probably do want to be sure
		// about the remote end's IP.

		// I think this is correct: contexts associated with the underlying connection
		// are derived from the node's lifecycle context.
		ConnContext: func(context.Context, *quic.ClientInfo) (context.Context, error) {
			return connContext, nil
		},

		// Skip: Tracer: we aren't interested in tracing quite yet.
	}
}

func StartListener(
	baseTLSConf *tls.Config,
	caPool *dcert.Pool,
	quicConf *quic.Config,
	qt *quic.Transport,
) (*quic.Listener, error) {
	conf := baseTLSConf.Clone()
	conf.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		innerConf := baseTLSConf.Clone()
		innerConf.ClientCAs = caPool.CertPool()

		return innerConf, nil
	}

	ql, err := qt.Listen(conf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("failed to set up QUIC listener: %w", err)
	}

	return ql, nil
}

func DefaultConfig() *quic.Config {
	return &quic.Config{
		// Skip: GetConfigForClient: don't need it yet.
		// Skip: Versions: maybe we force this to the current version, if there is a good reason to avoid older versions?

		// Defaults to 5 otherwise, which is far higher latency than we probably need.
		HandshakeIdleTimeout: 2 * time.Second,

		// Skip: MaxIdleTimeout: defaults to 30s of no activity whatsoever before closing a connection.

		// Skip: TokenStore: not clear how to use this yet.

		// Initial size of stream-level flow control window.
		// Just an estimate for now.
		InitialStreamReceiveWindow: 32 * 1024,

		// Max size of stream-level flow control window.
		// Just an estimate for now.
		MaxStreamReceiveWindow: 1024 * 1024,

		// Those windows were individual streams, this is for an entire connection.
		// Also a total estimate for now.
		InitialConnectionReceiveWindow: 4 * 32 * 1024,
		MaxConnectionReceiveWindow:     8 * 1024 * 1024,

		// Skip: AllowConnectionWindowIncrease: we don't need a callback on this, at this point.

		// How many bidirectional streams allowed on a single connection.
		// There is one bidirectional stream for establishing the basic p2p connection,
		// and there is one bidirectional stream for each active breathcast session.
		MaxIncomingStreams: 120,

		// Wingspan outbound workers are used for each connected peer,
		// for each voting session.
		// Assuming committing session, current voting, and maybe a couple invalid heights,
		// this ought to be plenty of headroom to avoid blocking new incoming streams.
		MaxIncomingUniStreams: 60,

		// Skip: KeepAlivePeriod: for now assuming we don't need keepalives,
		// but that could change if we find idle timeouts happening.

		// Skip: InitialPacketSize: "usually not necessary to manually set this value".

		// Skip: DisablePathMTUDiscovery: I think we want this on by default.

		// Skip: Allow0RTT: I don't know enough about this to say whether we should use/allow it yet.

		// Datagrams are practically the whole point of using QUIC here.
		EnableDatagrams: true,

		// Skip: Tracer: Don't want this yet.
	}
}
