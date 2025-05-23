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

	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/dview"
	"github.com/gordian-engine/dragon/internal/dk"
	"github.com/gordian-engine/dragon/internal/dprotoi"
	"github.com/gordian-engine/dragon/internal/dprotoi/dbootstrap/dbsacceptjoin"
	"github.com/gordian-engine/dragon/internal/dprotoi/dbootstrap/dbsacceptneighbor"
	"github.com/gordian-engine/dragon/internal/dprotoi/dbootstrap/dbsinbound"
	"github.com/gordian-engine/dragon/internal/dprotoi/dbootstrap/dbssendjoin"
	"github.com/gordian-engine/dragon/internal/dquic"
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

	caPool *dcert.Pool

	dialer dquic.Dialer

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

	// Dragon internals write to this channel
	// to notify the application of connection changes in the active view.
	ConnectionChanges chan<- dconn.Change
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
	// Delegate to the dquic package so we can use
	// an identical default configuration in tests.
	return dquic.DefaultConfig()
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
	qt := dquic.MakeTransport(ctx, cfg.UDPConn)

	neighborRequestsCh := make(chan string, 8) // Arbitrarily sized.

	k := dk.NewKernel(ctx, log.With("node_sys", "kernel"), dk.KernelConfig{
		ViewManager:      cfg.ViewManager,
		NeighborRequests: neighborRequestsCh,

		ShuffleSignal: cfg.ShuffleSignal,

		ConnectionChanges: cfg.ConnectionChanges,
	})

	baseTLSConf := cfg.customizedTLSConfig(log)
	caPool := dcert.NewPoolFromCerts(cfg.InitialTrustedCAs)

	n := &Node{
		log: log,

		k: k,

		quicTransport: qt,
		quicConf:      cfg.QUIC,

		baseTLSConf: baseTLSConf,

		caPool: caPool,

		dialer: dquic.Dialer{
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

		NewPeeringRequests: n.k.Requests().AddActivePeerRequests,

		AdvertiseAddr: n.advertiseAddr,

		// TODO: we should probably not rely on
		// this particular method of getting our certificate.
		Cert: n.baseTLSConf.Certificates[0],
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
	// that only gets updated once the dcert.Pool is updated.
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

		chain, err := dcert.NewChainFromTLSConnectionState(qc.ConnectionState().TLS)
		if err != nil {
			n.log.Warn(
				"Connection was accepted but chain extraction failed",
				"remote_addr", qc.RemoteAddr().String(),
				"err", err,
			)

			if err := qc.CloseWithError(1, "TODO: error extracting chain"); err != nil {
				n.log.Info(
					"Failed to close connection after failure to extract chain",
					"remote_addr", qc.RemoteAddr().String(),
					"err", err,
				)
			}

			continue
		}

		p := dbsinbound.Protocol{
			Log:  n.log.With("protocol", "incoming_bootstrap"),
			Conn: qc,

			PeerCert: chain.Leaf,

			Cfg: dbsinbound.Config{
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
			if err := res.JoinMessage.AA.VerifySignature(chain.Leaf); err != nil {
				n.log.Warn(
					"Accepted connection from valid peer but address attestation signature failed",
					"err", err,
				)

				if err := qc.CloseWithError(1, "TODO: error verifying address attestation signature"); err != nil {
					n.log.Info(
						"Failed to close connection after AA signature failure",
						"remote_addr", qc.RemoteAddr().String(),
						"err", err,
					)
				}

				continue
			}
			if err := n.handleIncomingJoin(ctx, qc, res.AdmissionStream, chain, *res.JoinMessage); err != nil {
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

		if res.NeighborMessage != nil {
			if err := n.handleIncomingNeighbor(ctx, qc, res.AdmissionStream, chain, *res.NeighborMessage); err != nil {
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
	chain dcert.Chain, jm dprotoi.JoinMessage,
) error {
	// Now we have the advertise address and an admission stream.
	peer := dview.ActivePeer{
		Chain:      chain,
		AA:         jm.AA,
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
	case n.k.Requests().JoinRequests <- req:
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

	p := dbsacceptjoin.Protocol{
		Log: n.log.With(
			"protocol", "accept_join",
			"remote_addr", qc.RemoteAddr().String(),
		),

		Cfg: dbsacceptjoin.Config{
			NeighborRequestTimeout: 100 * time.Millisecond,
			NeighborReplyTimeout:   100 * time.Millisecond,
		},

		Conn: qc,

		AdmissionStream: qs,
	}

	if _, err := p.Run(ctx); err != nil {
		return fmt.Errorf("failed to accept join: %w", err)
	}

	// Finally, the streams are initialized,
	// so we can pass the connection to the kernel now.
	pResp := make(chan dk.AddActivePeerResponse, 1)
	pReq := dk.AddActivePeerRequest{
		QuicConn: qc,

		Chain: chain,

		AdmissionStream: qs,

		Resp: pResp,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while sending peering request to kernel: %w",
			context.Cause(ctx),
		)

	case n.k.Requests().AddActivePeerRequests <- pReq:
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
	ctx context.Context,
	qc quic.Connection, qs quic.Stream,
	chain dcert.Chain, nm dprotoi.NeighborMessage,
) error {
	// We received a neighbor message from the remote.
	// Next, we have to consult the kernel to decide whether we will accept this neighbor request.
	peer := dview.ActivePeer{
		Chain:      chain,
		AA:         nm.AA,
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
	case n.k.Requests().NeighborDecisionRequests <- req:
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
		p := dbsacceptneighbor.Protocol{
			Log: n.log.With(
				"protocol", "reject_neighbor",
			),
			Conn:      qc,
			Admission: qs,

			Cfg: dbsacceptneighbor.Config{
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
	p := dbsacceptneighbor.Protocol{
		Log: n.log.With(
			"protocol", "accept_neighbor",
		),
		Conn:      qc,
		Admission: qs,

		Cfg: dbsacceptneighbor.Config{
			NeighborReplyTimeout: 50 * time.Millisecond,
		},
	}

	if _, err := p.RunAccept(ctx); err != nil {
		// We don't need to close the connection here,
		// because the caller closes the connection upon error.
		return fmt.Errorf("failed while accepting neighbor request: %w", err)
	}

	// Streams are initialized, so we can seend the peering to the kernel.
	pResp := make(chan dk.AddActivePeerResponse, 1)
	pReq := dk.AddActivePeerRequest{
		QuicConn: qc,

		Chain: chain,
		AA:    nm.AA,

		AdmissionStream: qs,

		Resp: pResp,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context cancelled while sending peering request to kernel: %w",
			context.Cause(ctx),
		)

	case n.k.Requests().AddActivePeerRequests <- pReq:
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
// If the node already has a connection to the given address,
// the method returns [AlreadyConnectedToAddrError].
//
// If the contact node disconnects, we have no indication of whether
// they chose to forward the join message to their peers.
// TODO: we should have DisconnectedError or something to specifically indicate
// that semi-expected disconnect.
func (n *Node) DialAndJoin(ctx context.Context, addr net.Addr) error {
	// DialAndJoin should be a very rare call -- maybe a couple times during startup,
	// and then the p2p mesh should be stable.
	// Nonetheless, if we had some initial list of say 5 nodes to connect to,
	// it is possible that by attempting to join the first node,
	// we could naturally make a connection to one of the later nodes in the list.
	// So, we have a few extra checks to avoid duplicating connections.

	// Before even dialing, ask the kernel if there is
	// existing connection with the given address.
	hasConn, err := n.k.HasConnectionToAddress(ctx, addr.String())
	if err != nil {
		return fmt.Errorf(
			"DialAndJoin: failed to check for existing connection to address: %w",
			err,
		)
	}

	if hasConn {
		return fmt.Errorf(
			"DialAndJoin: refusing to connect: %w",
			AlreadyConnectedToAddrError{Addr: addr.String()},
		)
	}

	dr, err := n.dialer.Dial(ctx, addr)
	if err != nil {
		return fmt.Errorf("DialAndJoin: dial failed: %w", err)
	}

	chain, err := dcert.NewChainFromTLSConnectionState(dr.Conn.ConnectionState().TLS)
	if err != nil {
		return fmt.Errorf("DialAndJoin: failed to extract certificate chain: %w", err)
	}

	hasConn, err = n.k.HasConnectionToChain(ctx, chain)
	if err != nil {
		return fmt.Errorf(
			"DialAndJoin: failed to check for existing connection to chain: %w",
			err,
		)
	}
	if hasConn {
		return fmt.Errorf(
			"DialAndJoin: dropping connection whose chain matches existing connection: %w",
			AlreadyConnectedToCertError{Chain: chain},
		)
	}

	// TODO: start a new goroutine for a context.WithCancelCause paired with notify.

	res, err := n.bootstrapJoin(ctx, dr.Conn)
	if err != nil {
		return fmt.Errorf("DialAndJoin: failed to bootstrap: %w", err)
	}

	// The bootstrap process completed successfully,
	// so now the last step is to confirm peering with the kernel.
	pResp := make(chan dk.AddActivePeerResponse, 1)
	req := dk.AddActivePeerRequest{
		QuicConn: dr.Conn,

		Chain: chain,
		AA:    res.AA,

		AdmissionStream: res.AdmissionStream,

		Resp: pResp,
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)

	case n.k.Requests().AddActivePeerRequests <- req:
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

// bootstrapJoin bootstraps the protocol streams on the given connection.
func (n *Node) bootstrapJoin(
	ctx context.Context, qc quic.Connection,
) (dbssendjoin.Result, error) {
	p := dbssendjoin.Protocol{
		Log:  n.log.With("protocol", "outgoing_bootstrap_join"),
		Conn: qc,
		Cfg: dbssendjoin.Config{
			AdvertiseAddr: n.advertiseAddr,

			// TODO: for now these are all hardcoded,
			// but they need to be configurable.
			OpenStreamTimeout:    100 * time.Millisecond,
			AwaitNeighborTimeout: 100 * time.Millisecond,

			// TODO: we should probably not rely on
			// this particular method of getting our certificate.
			Cert: n.baseTLSConf.Certificates[0],
		},
	}

	res, err := p.Run(ctx)
	if err != nil {
		return res, fmt.Errorf("bootstrap by join failed: %w", err)
	}

	return res, nil
}

// UpdateCAs replaces the existing trusted CAs
// with the given list.
func (n *Node) UpdateCAs(certs []*x509.Certificate) {
	n.caPool.UpdateCAs(certs)
}

func (n *Node) ActiveViewSize() int {
	// Temporary shim for tests.
	return n.k.GetActiveViewSize()
}
