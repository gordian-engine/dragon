package dragon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"dragon.example/dragon/dca"
	"dragon.example/dragon/deval"
	"dragon.example/dragon/internal/dk"
	"github.com/quic-go/quic-go"
)

// Node is a node in the p2p layer.
// It contains a QUIC listener, and a number of live connections to other nodes.
type Node struct {
	log *slog.Logger

	k *dk.Kernel

	wg sync.WaitGroup

	quicConf      *quic.Config
	quicTransport *quic.Transport
	quicListener  *quic.Listener

	// This is a modified version of the TLS config provided via the Node config.
	// We never use this directly, but we do clone it when we need TLS config.
	baseTLSConf *tls.Config

	caPool *dca.Pool

	advertiseAddr string
}

// NodeConfig is the configuration for a [Node].
type NodeConfig struct {
	UDPConn *net.UDPConn
	QUIC    *quic.Config

	// The base TLS configuration to use.
	// The Node will clone it and modify the clone.
	TLS *tls.Config

	InitialTrustedCAs []*x509.Certificate

	// The address to advertise for this Node
	// when sending out a Join message.
	AdvertiseAddr string

	// The maximum number of incoming connections that can be live
	// but which have not yet resolved into a peering or have been closed.
	// If zero, a reasonable default will be used.
	IncomingPendingConnectionLimit uint8

	// Determines the behavior of choosing to accept peer connections.
	PeerEvaluator deval.PeerEvaluator
}

// validate panics if there are any illegal settings in the configuration.
// It also warns about any suspect settings.
func (c NodeConfig) validate(log *slog.Logger) {
	if !c.QUIC.EnableDatagrams {
		// We aren't actually forcing this yet.
		// It's possible this may only be an application-level concern.
		panic(errors.New("QUIC datagrams must be enabled; set NodeConfig.QUIC.EnableDatagrams=true"))
	}

	if c.TLS.ClientAuth != tls.RequireAndVerifyClientCert {
		panic(errors.New(
			"client certificates are required; set NodeConfig.TLS.ClientAuth = tls.RequireAndVerifyClientCert",
		))
	}

	if c.AdvertiseAddr == "" {
		panic(errors.New("NodeConfig.AdvertiseAddr must not be empty"))
	}

	if c.PeerEvaluator == nil {
		panic(errors.New("NodeConfig.PeerEvaluator may not be nil"))
	}

	// Although we customize the TLS config later in the initialization flow,
	// we don't touch the certificates.
	// So it's fine to directly inspect them now,
	// in order to helpfully log any obvious misconfigurations.

	// For now we are assuming that the certificate is only set via
	// the first entry in Certificates.
	// We could be smarter about this, and consult the callback fields,
	// which we may end up using anyway.
	if len(c.TLS.Certificates) > 0 {
		cert := c.TLS.Certificates[0]
		if cert.Leaf == nil {
			// The leaf field would be lazily initialized anyway,
			// so we are just doing this work sooner than otherwise.
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				panic(fmt.Errorf("failed to parse leaf certificate: %w", err))
			}

			cert.Leaf = leaf
		}

		// Timestamp validation.
		now := time.Now()
		if cert.Leaf.NotBefore.After(now) {
			log.Error(
				"Certificate's not before field is in the future",
				"not_before", cert.Leaf.NotBefore,
			)
		}
		if cert.Leaf.NotAfter.Before(now) {
			log.Error(
				"Certificate's not after field is in the past",
				"not_after", cert.Leaf.NotAfter,
			)
		}

		// Now, the trickier part, key usage.
		if cert.Leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			log.Error(
				"Certificate is missing digital signature key usage; remotes may reject TLS communication",
			)
		}

		if !slices.Contains(cert.Leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
			log.Error(
				"Certificate is missing server authentication extended key usage; clients will reject TLS handshake",
			)
		}

		if !slices.Contains(cert.Leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
			log.Error(
				"Certificate is missing client authentication extended key usage; servers will reject TLS handshake",
			)
		}
	}
}

func (c NodeConfig) customizedTLSConfig(log *slog.Logger) *tls.Config {
	// Assume we can't take ownership of the input TLS config,
	// given that we are intending to modify it.
	conf := c.TLS.Clone()

	// The config has a set of initial trusted CAs.
	// Build a certificate pool with only those CAs,
	// and set that as both the serverside and clientside pool,
	// so that it verifies the same whether we are initiating or receiving a connection.
	//
	// This is just the current simple strategy.
	// There are two obvious ways to go from here to handle dynamic CA sets.
	//
	// 1. Have the server use GetConfigForClient, which will consult the dynamic CA set
	//    based on the client hello info, decide whether to accept or reject,
	//    and if accept then return a TLS config that has a pool only trusting
	//    that particular client's CA.
	//    For the client, the TLS configuration can be generated on demand
	//    when we dial a peer, so we can set a different RootCAs pool.
	// 2. Since we are using the quic.Transport, we could potentially
	//    stop the listener (which does not affect running connections,
	//    but may disconnect handshaking connections)
	//    and restart it with an updated TLS config.
	// 3. Much less obvious, we could use a single certificate pool,
	//    but add every cert using the (*x509.CertPool).AddCertWithConstraint method,
	//    which takes a callback to be evaluated any time the certificate
	//    would be considered for validity.
	//    The downside of this approach is that in a high churn set of CAs,
	//    our certificate pool would never shrink.
	//
	// The first solution seems much more in line with the intended use of TLS configs.
	//
	// To be clear, the underlying issue is certificates cannot be removed from a pool.
	// We have to use a new TLS config with a different pool any time a certificate is removed.

	if conf.RootCAs != nil {
		log.Warn("Node's TLS configuration had RootCAs set; those CAs will be ignored")
	}
	if conf.ClientCAs != nil {
		log.Warn("Node's TLS configuration had ClientCAs set; those CAs will be ignored")
	}

	emptyPool := x509.NewCertPool()
	conf.RootCAs = emptyPool
	conf.ClientCAs = emptyPool

	return conf
}

// DefaultQUICConfig is the default QUIC configuration for a [NodeConfig].
func DefaultQUICConfig() *quic.Config {
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
		MaxConnectionReceiveWindow:     4 * 1024 * 1024,

		// Skip: AllowConnectionWindowIncrease: we don't need a callback on this, at this point.

		// How many streams allowed on a single connection.
		// Just an estimate for now.
		MaxIncomingStreams:    6, // Bidirectional.
		MaxIncomingUniStreams: 6,

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

// NewNode returns a new Node with the given configuration.
// The ctx parameter controls the lifecycle of the Node;
// cancel the context to stop the node,
// and then use [(*Node).Wait] to block until all background work has completed.
//
// NewNode returns runtime errors that happen during initialization.
// Configuration errors cause a panic.
func NewNode(ctx context.Context, log *slog.Logger, cfg NodeConfig) (*Node, error) {
	// Panic if there are any misconfigurations.
	cfg.validate(log)

	// We are using a quic Transport directly here in order to have
	// finer control over connection behavior than a simple call to quic.Listen.
	qt := &quic.Transport{
		Conn: cfg.UDPConn,

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
		ConnContext: func(context.Context) context.Context {
			return ctx
		},

		// Skip: Tracer: we aren't interested in tracing quite yet.
	}

	k := dk.NewKernel(ctx, log.With("node_sys", "kernel"), dk.KernelConfig{
		PeerEvaluator: cfg.PeerEvaluator,
	})

	n := &Node{
		log: log,

		k: k,

		quicTransport: qt,

		quicConf:    cfg.QUIC,
		baseTLSConf: cfg.customizedTLSConfig(log),

		caPool: dca.NewPoolFromCerts(cfg.InitialTrustedCAs),

		advertiseAddr: cfg.AdvertiseAddr,
	}

	if err := n.startListener(); err != nil {
		// Assume error already wrapped.
		return nil, err
	}

	nPending := cfg.IncomingPendingConnectionLimit
	if nPending == 0 {
		nPending = 4
	}

	n.wg.Add(int(nPending))
	for range nPending {
		go n.acceptConnections(ctx)
	}
	return n, nil
}

// startListener starts the QUIC listener
// and assigns the listener to n.quicListener.
func (n *Node) startListener() error {
	// By setting GetConfigForClient on the TLS config for the listener,
	// we can dynamically set the ClientCAs certificate pool
	// any time a client connects.
	tlsConf := n.baseTLSConf.Clone()
	tlsConf.GetConfigForClient = n.getQUICListenerTLCConfig

	ql, err := n.quicTransport.Listen(tlsConf, n.quicConf)
	if err != nil {
		return fmt.Errorf("failed to set up QUIC listener: %w", err)
	}

	n.quicListener = ql
	return nil
}

// getQUICListenerTLCConfig is used as the GetConfigForClient callback
// in the tls.Config that the QUIC listener uses.
//
// Dynamically retrieiving the TLS config allows us to have an up-to-date TLS config
func (n *Node) getQUICListenerTLCConfig(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	// TOOD: right now we build a new TLS config for every incoming client connection,
	// but we should be able to create a single shared instance
	// that only gets updated once the dca.Pool is updated.
	tlsConf := n.baseTLSConf.Clone()

	// For the QUIC listener,
	// we only need to set ClientCAs to verify incoming certificates;
	// RootCAs would be for outgoing connections,
	// and we do not initiate any outgoing connections from the listener.
	//
	// Alternatively, it might be possible to inspect the ClientHelloInfo
	// to create a certificate pool that only supports the client's CA,
	// but that probably wouldn't give us any measurable benefit.
	tlsConf.ClientCAs = n.caPool.CertPool()

	return tlsConf, nil
}

// Wait blocks until the node has finished all background work.
func (n *Node) Wait() {
	n.wg.Wait()
	n.k.Wait()
}

// acceptConnections handles incoming new connections to the node's listener.
// This runs in multiple, independent goroutines,
// effectively limiting the number of pending
// (as in opened but not yet peered) connections.
func (n *Node) acceptConnections(ctx context.Context) {
	defer n.wg.Done()

	for {
		qc, err := n.quicListener.Accept(ctx)
		if err != nil {
			if errors.Is(context.Cause(ctx), err) {
				n.log.Info("Accept loop quitting due to context cancellation", "cause", context.Cause(ctx))
				return
			}
		}

		// TODO: this should have some early rate-limiting based on remote identity.

		ic := &inboundConnection{
			log:   n.log.With("remote_conn", qc.RemoteAddr().String()),
			qConn: qc,

			k: n.k,
		}
		ic.log.Info("Connection accepted")

		if err := ic.HandleIncomingStream(ctx); err != nil {
			ic.log.Info("Failed to handle incoming stream", "err", err)

			// Since there was an error, try to close the connection.
			if err := qc.CloseWithError(1, "TODO (inbound stream)"); err != nil {
				ic.log.Debug("Failed to send close message to peer", "err", err)
			}

			// And if the error was context-related, stop now.
			if cause := context.Cause(ctx); cause != nil && errors.Is(err, cause) {
				n.log.Info("Accept loop quitting due to context cancellation", "cause", cause)
				return
			}
		}
	}
}

// DialPeer opens a QUIC connection to the given address,
// which is expected to be another DRAGON participant.
//
// Once the dial completes, in standard behavior,
// the client will call [(*UnpeeredConnection.Join)] to join the network,
// or the client will send a Neighbor message to create a pairing.
func (n *Node) DialPeer(ctx context.Context, addr net.Addr) (*UnpeeredConnection, error) {
	// When dialing a peer, we need to use the most recent CA pool.
	tlsConf := n.baseTLSConf.Clone()
	tlsConf.RootCAs = n.caPool.CertPool()

	qc, err := n.quicTransport.Dial(ctx, addr, tlsConf, n.quicConf)
	if err != nil {
		return nil, fmt.Errorf("DialPeer: dial failed: %w", err)
	}

	return &UnpeeredConnection{
		log:   n.log.With("remote_addr", qc.RemoteAddr().String()),
		qConn: qc,

		n: n,
	}, nil
}

func (n *Node) ActiveViewSize() int {
	return n.k.GetActiveViewSize()
}
