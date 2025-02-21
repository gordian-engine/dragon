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

	"github.com/gordian-engine/dragon/dca"
	"github.com/gordian-engine/dragon/dview"
	"github.com/gordian-engine/dragon/internal/dk"
	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/gordian-engine/dragon/internal/dproto/dbsaj"
	"github.com/gordian-engine/dragon/internal/dproto/dbsan"
	"github.com/gordian-engine/dragon/internal/dproto/dbsin"
	"github.com/gordian-engine/dragon/internal/dproto/dbsjoin"
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

	dialer dialer

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

	// Manages the active and passive peers.
	ViewManager dview.Manager

	// Externally controlled channel to signal when
	// this node should initiate an outgoing shuffle.
	ShuffleSignal <-chan struct{}
}

// validate panics if there are any illegal settings in the configuration.
// It also warns about any suspect settings.
func (c NodeConfig) validate(log *slog.Logger) {
	// If there are multiple reasons we could panic,
	// collect them all in one go
	// so we can give a maximally helpful error.
	var panicErrs error

	if !c.QUIC.EnableDatagrams {
		// We aren't actually forcing this yet.
		// It's possible this may only be an application-level concern.
		panicErrs = errors.Join(
			panicErrs,
			errors.New("QUIC datagrams must be enabled; set NodeConfig.QUIC.EnableDatagrams=true"),
		)
	}

	if c.TLS.ClientAuth != tls.RequireAndVerifyClientCert {
		panicErrs = errors.Join(
			panicErrs,
			errors.New("client certificates are required; set NodeConfig.TLS.ClientAuth = tls.RequireAndVerifyClientCert"),
		)
	}

	if c.AdvertiseAddr == "" {
		panicErrs = errors.Join(
			panicErrs,
			errors.New("NodeConfig.AdvertiseAddr must not be empty"),
		)
	}

	if c.ViewManager == nil {
		panicErrs = errors.Join(
			panicErrs,
			errors.New("NodeConfig.ViewManager may not be nil"),
		)
	}

	if c.ShuffleSignal == nil {
		panicErrs = errors.Join(
			panicErrs,
			errors.New("NodeConfig.ShuffleSignal may not be nil"),
		)

		if cap(c.ShuffleSignal) != 0 {
			panicErrs = errors.Join(
				panicErrs,
				errors.New("NodeConfig.ShuffleSignal must be an unbuffered channel for correct behavior"),
			)
		}
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
			panicErrs = errors.Join(
				panicErrs,
				errors.New("BUG: TLS.Certificates[0].Leaf must be set (use x509.ParseCertificate if needed)"),
			)
		}

		if cert.Leaf != nil {
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

	if panicErrs != nil {
		panic(panicErrs)
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

	neighborRequestsCh := make(chan string, 8) // Arbitrarily sized.

	k := dk.NewKernel(ctx, log.With("node_sys", "kernel"), dk.KernelConfig{
		ViewManager:      cfg.ViewManager,
		NeighborRequests: neighborRequestsCh,
	})

	baseTLSConf := cfg.customizedTLSConfig(log)
	caPool := dca.NewPoolFromCerts(cfg.InitialTrustedCAs)

	n := &Node{
		log: log,

		k: k,

		quicTransport: qt,
		quicConf:      cfg.QUIC,

		baseTLSConf: baseTLSConf,

		caPool: caPool,

		dialer: dialer{
			BaseTLSConf: baseTLSConf,

			QUICTransport: qt,
			QUICConfig:    cfg.QUIC,

			CAPool: caPool,
		},

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

	// For now, limit neighborDialer to one instance
	// which means we can only dial one neighbor at a time.
	// We could probably safely increase this.
	n.wg.Add(1)
	nd := &neighborDialer{
		Log: n.log.With("node_sys", "neighbor_dialer"),

		Dialer: n.dialer,

		NeighborRequests: neighborRequestsCh,

		NewPeeringRequests: k.NewPeeringRequests,
	}
	go nd.Run(ctx, &n.wg)

	return n, nil
}

// startListener starts the QUIC listener
// and assigns the listener to n.quicListener.
func (n *Node) startListener() error {
	// By setting GetConfigForClient on the TLS config for the listener,
	// we can dynamically set the ClientCAs certificate pool
	// any time a client connects.
	tlsConf := n.baseTLSConf.Clone()
	tlsConf.GetConfigForClient = n.getQUICListenerTLSConfig

	ql, err := n.quicTransport.Listen(tlsConf, n.quicConf)
	if err != nil {
		return fmt.Errorf("failed to set up QUIC listener: %w", err)
	}

	n.quicListener = ql
	return nil
}

// getQUICListenerTLSConfig is used as the GetConfigForClient callback
// in the tls.Config that the QUIC listener uses.
//
// Dynamically retrieiving the TLS config allows us to have an up-to-date TLS config
// any time an incoming connection arrives.
func (n *Node) getQUICListenerTLSConfig(*tls.ClientHelloInfo) (*tls.Config, error) {
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

// acceptConnections accepts incoming connections,
// does any required initialization work,
// and informs the kernel of the finished connection upon success.
//
// This runs in multiple, independent goroutines,
// effectively limiting the number of pending
// (as in opened but not yet peered) connections.
func (n *Node) acceptConnections(ctx context.Context) {
	defer n.wg.Done()

	for {
		qc, err := n.quicListener.Accept(ctx)
		if err != nil {
			if errors.Is(context.Cause(ctx), err) {
				n.log.Info(
					"Accept loop quitting due to context cancellation when accepting connection",
					"cause", context.Cause(ctx),
				)
				return
			}

			// Debug-level because this could be spammy if we are getting a lot of garbage connections.
			n.log.Debug(
				"Failed to accept incoming connection",
				"err", err,
			)
			continue
		}

		// TODO: this should have some early rate-limiting based on remote identity.

		// TODO: update context to handle notify on certificate removal.

		p := dbsin.Protocol{
			Log:  n.log.With("protocol", "incoming_bootstrap"),
			Conn: qc,

			// The first element of PeerCertificates is supposed to be the leaf certificate.
			PeerCert: qc.ConnectionState().TLS.PeerCertificates[0],

			Cfg: dbsin.Config{
				AcceptBootstrapStreamTimeout: time.Second,

				ReadStreamHeaderTimeout: time.Second,

				GraceBeforeJoinTimestamp: 2 * time.Second,
				GraceAfterJoinTimestamp:  2 * time.Second,
			},
		}

		res, err := p.Run(ctx)
		if err != nil {
			if errors.Is(context.Cause(ctx), err) {
				n.log.Info(
					"Accept loop quitting due to context cancellation during incoming bootstrap",
					"remote_addr", qc.RemoteAddr().String(),
					"cause", context.Cause(ctx),
				)
				return
			}

			// Now info level should be okay since we got past TLS handshaking.
			n.log.Info(
				"Failed to handle incoming bootstrap",
				"remote_addr", qc.RemoteAddr().String(),
				"err", err,
			)

			if err := qc.CloseWithError(1, "TODO: error handling incoming bootstrap"); err != nil {
				n.log.Info(
					"Failed to close connection after failing to handle incoming bootstrap",
					"remote_addr", qc.RemoteAddr().String(),
					"err", err,
				)
			}
			continue
		}

		if res.JoinMessage != nil {
			if err := n.handleIncomingJoin(ctx, qc, res.AdmissionStream, *res.JoinMessage); err != nil {
				// On error, assume we have to close the connection.
				if errors.Is(context.Cause(ctx), err) {
					n.log.Info(
						"Accept loop quitting due to context cancellation during handling incoming join",
						"remote_addr", qc.RemoteAddr().String(),
						"cause", context.Cause(ctx),
					)
					return
				}

				if err := qc.CloseWithError(1, "TODO: error handling incoming join"); err != nil {
					n.log.Info(
						"Failed to close connection after failing to handle incoming join",
						"remote_addr", qc.RemoteAddr().String(),
						"err", err,
					)
				}
			}

			// Whether the join was handled successfully,
			// or whether there was an error and we had to close the connection,
			// we go ahead to the next iteration of accepting connections now.
			continue
		}

		if res.NeighborMessage {
			if err := n.handleIncomingNeighbor(ctx, qc, res.AdmissionStream); err != nil {
				// On error, assume we have to close the connection.
				if errors.Is(context.Cause(ctx), err) {
					n.log.Info(
						"Accept loop quitting due to context cancellation during handling incoming neighbor request",
						"remote_addr", qc.RemoteAddr().String(),
						"cause", context.Cause(ctx),
					)
					return
				}

				if err := qc.CloseWithError(1, "TODO: error handling incoming neighbor request"); err != nil {
					n.log.Info(
						"Failed to close connection after failing to handle incoming neighbor request",
						"remote_addr", qc.RemoteAddr().String(),
						"err", err,
					)
				}
			}

			// Whether the connection was handled properly or failed,
			// continue to the next iteration of accepting connections.
			continue
		}

		panic(errors.New(
			"BUG: bootstrap input protocol did not indicate join or neighbor message",
		))
	}
}

func (n *Node) handleIncomingJoin(
	ctx context.Context, qc quic.Connection, qs quic.Stream,
	jm dproto.JoinMessage,
) error {
	// Now we have the advertise address and an admission stream.
	peer := dview.ActivePeer{
		TLS:        qc.ConnectionState().TLS,
		LocalAddr:  qc.LocalAddr(),
		RemoteAddr: qc.RemoteAddr(),
	}
	respCh := make(chan dk.JoinResponse, 1)
	req := dk.JoinRequest{
		Peer: peer,
		Msg:  jm,
		Resp: respCh,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while sending join request to kernel: %w", context.Cause(ctx),
		)
	case n.k.JoinRequests <- req:
		// Okay.
	}

	var resp dk.JoinResponse
	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while awaiting join response from kernel: %w", context.Cause(ctx),
		)
	case resp = <-respCh:
		// Okay.
	}

	if resp.Decision == dk.DisconnectJoinDecision {
		// The kernel may or may not be forwarding join to other peers.
		// It doesn't make a difference here:
		// we have to close the connection.
		if err := qc.CloseWithError(1, "TODO: join request denied"); err != nil {
			n.log.Info(
				"Failed to close connection after denying join request",
				"remote_addr", peer.RemoteAddr.String(),
				"err", err,
			)
		}

		// We've handled the join to completion.
		return nil
	}

	// It wasn't a disconnect, so it must be an accept.
	if resp.Decision != dk.AcceptJoinDecision {
		panic(fmt.Errorf(
			"IMPOSSIBLE: kernel returned invalid join decision %v", resp.Decision,
		))
	}

	p := dbsaj.Protocol{
		Log: n.log.With(
			"protocol", "accept_join",
			"remote_addr", qc.RemoteAddr().String(),
		),

		Cfg: dbsaj.Config{
			NeighborRequestTimeout:   100 * time.Millisecond,
			NeighborReplyTimeout:     100 * time.Millisecond,
			InitializeStreamsTimeout: 100 * time.Millisecond,
		},

		Conn: qc,

		AdmissionStream: qs,
	}

	res, err := p.Run(ctx)
	if err != nil {
		return fmt.Errorf("failed to accept join: %w", err)
	}

	// Finally, the streams are initialized,
	// so we can pass the connection to the kernel now.
	pResp := make(chan dk.NewPeeringResponse, 1)
	pReq := dk.NewPeeringRequest{
		QuicConn: qc,

		AdmissionStream:  qs,
		DisconnectStream: res.Disconnect,
		ShuffleStream:    res.Shuffle,

		Resp: pResp,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while sending peering request to kernel: %w",
			context.Cause(ctx),
		)

	case n.k.NewPeeringRequests <- pReq:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while awaiting peering response from kernel: %w",
			context.Cause(ctx),
		)
	case resp := <-pResp:
		if resp.RejectReason != "" {
			// Last minute issue with adding the connection.
			// For now, just return the error, and the caller will close the connection.
			return fmt.Errorf("kernel rejected finalized peering: %s", resp.RejectReason)
		}

		// Otherwise there was no reject reason,
		// so the kernel accepted the peering.
		// We are finished accepting this connection,
		// and now the accept loop can continue.
		return nil
	}
}

func (n *Node) handleIncomingNeighbor(
	ctx context.Context, qc quic.Connection, qs quic.Stream,
) error {
	// We received a neighbor message from the remote.
	// Next, we have to consult the kernel to decide whether we will accept this neighbor request.
	peer := dview.ActivePeer{
		TLS:        qc.ConnectionState().TLS,
		LocalAddr:  qc.LocalAddr(),
		RemoteAddr: qc.RemoteAddr(),
	}
	respCh := make(chan bool, 1)
	req := dk.NeighborDecisionRequest{
		Peer: peer,
		Resp: respCh,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while sending neighbor decision request to kernel: %w",
			context.Cause(ctx),
		)
	case n.k.NeighborDecisionRequests <- req:
		// Okay.
	}

	var accept bool
	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while awaiting neighbor decision request from kernel: %w",
			context.Cause(ctx),
		)
	case accept = <-respCh:
		// Okay.
	}

	if !accept {
		p := dbsan.Protocol{
			Log: n.log.With(
				"protocol", "reject_neighbor",
			),
			Conn:      qc,
			Admission: qs,

			Cfg: dbsan.Config{
				NeighborReplyTimeout: 50 * time.Millisecond,
			},
		}
		if err := p.RunReject(ctx); err != nil {
			// We don't need to close the connection here,
			// because the caller closes the connection upon error.
			return fmt.Errorf("failed while rejecting neighbor request: %w", err)
		}

		return nil
	}

	// Otherwise we are accepting.
	p := dbsan.Protocol{
		Log: n.log.With(
			"protocol", "accept_neighbor",
		),
		Conn:      qc,
		Admission: qs,

		Cfg: dbsan.Config{
			NeighborReplyTimeout: 50 * time.Millisecond,
			AcceptStreamsTimeout: 75 * time.Millisecond,
		},
	}

	res, err := p.RunAccept(ctx)
	if err != nil {
		// We don't need to close the connection here,
		// because the caller closes the connection upon error.
		return fmt.Errorf("failed while accepting neighbor request: %w", err)
	}

	// Streams are initialized, so we can seend the peering to the kernel.
	pResp := make(chan dk.NewPeeringResponse, 1)
	pReq := dk.NewPeeringRequest{
		QuicConn: qc,

		AdmissionStream:  qs,
		DisconnectStream: res.Disconnect,
		ShuffleStream:    res.Shuffle,

		Resp: pResp,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while sending peering request to kernel: %w",
			context.Cause(ctx),
		)

	case n.k.NewPeeringRequests <- pReq:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while awaiting peering response from kernel: %w",
			context.Cause(ctx),
		)
	case resp := <-pResp:
		if resp.RejectReason != "" {
			// Last minute issue with adding the connection.
			// For now, just return the error, and the caller will close the connection.
			return fmt.Errorf("kernel rejected finalized peering: %s", resp.RejectReason)
		}

		// Otherwise there was no reject reason,
		// so the kernel accepted the peering.
		// We are finished accepting this connection,
		// and now the accept loop can continue.
		return nil
	}
}

// DialAndJoin attempts to join the p2p network by sending a Join mesage to addr.
//
// If the contact node makes a neighbor request back and we successfully peer,
// the returned error is nil.
//
// If the contact node disconnects, we have no indication of whether
// they chose to forward the join message to their peers.
// TODO: we should have DisconnectedError or something to specifically indicate
// that semi-expected disconnect.
func (n *Node) DialAndJoin(ctx context.Context, addr net.Addr) error {
	dr, err := n.dialer.Dial(ctx, addr)
	if err != nil {
		return fmt.Errorf("DialAndJoin: dial failed: %w", err)
	}

	// TODO: start a new goroutine for a context.WithCancelCause paired with notify.

	res, err := n.bootstrapJoin(ctx, dr.Conn)
	if err != nil {
		return fmt.Errorf("DialAndJoin: failed to bootstrap: %w", err)
	}

	// The bootstrap process completed successfully,
	// so now the last step is to confirm peering with the kernel.
	pResp := make(chan dk.NewPeeringResponse, 1)
	req := dk.NewPeeringRequest{
		QuicConn: dr.Conn,

		AdmissionStream:  res.AdmissionStream,
		DisconnectStream: res.DisconnectStream,
		ShuffleStream:    res.ShuffleStream,

		Resp: pResp,
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)

	case n.k.NewPeeringRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return context.Cause(ctx)

	case resp := <-pResp:
		if resp.RejectReason != "" {
			// Last minute issue with adding the connection.
			if err := dr.Conn.CloseWithError(1, "TODO: peering rejected: "+resp.RejectReason); err != nil {
				n.log.Debug("Failed to close connection", "err", err)
			}

			return fmt.Errorf("failed to join due to kernel rejecting peering: %s", resp.RejectReason)
		}

		// Otherwise it was accepted, and the Join is complete.
		return nil
	}
}

// bootstrapJoin bootstraps all protocol streams on the given connection.
func (n *Node) bootstrapJoin(
	ctx context.Context, qc quic.Connection,
) (dbsjoin.Result, error) {
	p := dbsjoin.Protocol{
		Log:  n.log.With("protocol", "outgoing_bootstrap_join"),
		Conn: qc,
		Cfg: dbsjoin.Config{
			AdvertiseAddr: n.advertiseAddr,

			// TODO: for now these are all hardcoded,
			// but they need to be configurable.
			OpenStreamTimeout:    100 * time.Millisecond,
			AwaitNeighborTimeout: 100 * time.Millisecond,
			AcceptStreamsTimeout: 100 * time.Millisecond,

			// TODO: we should probably not rely on
			// this particular method of getting our certificate.
			Cert: n.baseTLSConf.Certificates[0],

			// For now this is just hardcoded to time.Now,
			// but maybe it makes sense to inject something else for tests.
			NowFn: time.Now,
		},
	}

	res, err := p.Run(ctx)
	if err != nil {
		return res, fmt.Errorf("bootstrap by join failed: %w", err)
	}

	return res, nil
}

func (n *Node) UpdateCAs(certs []*x509.Certificate) {
	n.caPool.UpdateCAs(certs)
}

func (n *Node) ActiveViewSize() int {
	// Temporary shim for tests.
	return n.k.GetActiveViewSize()
}
