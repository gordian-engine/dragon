package dragon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Node is a node in the p2p layer.
// It contains a QUIC listener, and a number of live connections to other nodes.
type Node struct {
	log *slog.Logger

	wg sync.WaitGroup

	qt *quic.Transport

	quicConf *quic.Config
	tlsConf  *tls.Config
}

// NodeConfig is the configuration for a [Node].
type NodeConfig struct {
	UDPConn *net.UDPConn
	QUIC    *quic.Config
	TLS     *tls.Config

	// The maximum number of incoming connections that can be live
	// but which have not yet resolved into a peering or have been closed.
	// If zero, a reasonable default will be used.
	IncomingPendingConnections uint8
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
func NewNode(ctx context.Context, log *slog.Logger, cfg NodeConfig) (*Node, error) {
	if !cfg.QUIC.EnableDatagrams {
		panic(errors.New("gblockdist.Node requires QUIC datagrams; set cfg.Quic.EnableDatagrams=true"))
	}

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

	ql, err := qt.Listen(cfg.TLS, cfg.QUIC)
	if err != nil {
		return nil, fmt.Errorf("failed to set up QUIC listener: %w", err)
	}

	n := &Node{
		log: log,

		qt: qt,

		quicConf: cfg.QUIC,
		tlsConf:  cfg.TLS,
	}

	nPending := cfg.IncomingPendingConnections
	if nPending == 0 {
		nPending = 4
	}

	n.wg.Add(int(nPending))
	for range nPending {
		go n.acceptConnections(ctx, ql)
	}
	return n, nil
}

// Wait blocks until the node has finished all background work.
func (n *Node) Wait() {
	n.wg.Wait()
}

// acceptConnections handles incoming new connections to our listener.
// This runs in multiple, independent goroutines,
// effectively limiting the number of pending connections.
func (n *Node) acceptConnections(ctx context.Context, ql *quic.Listener) {
	defer n.wg.Done()

	for {
		qc, err := ql.Accept(ctx)
		if err != nil {
			if errors.Is(context.Cause(ctx), err) {
				n.log.Info("Accept loop quitting due to context cancellation", "cause", context.Cause(ctx))
				return
			}
		}

		// TODO: this should have some early rate-limiting based on remote identity.

		n.log.Info("Connection accepted")

		pc := &pendingConnection{
			log:   n.log.With("remote_conn", qc.RemoteAddr().String()),
			qConn: qc,
		}
		if err := pc.handleIncomingStreamHandshake(ctx); err != nil {
			pc.log.Info("Failed to handle incoming stream handshake", "err", err)

			if err := qc.CloseWithError(1, "TODO: REASON"); err != nil {
				pc.log.Debug("Failed to send close message to peer", "err", err)
			}

			continue
		}

		// The pending connection succeeded.
		// TODO: here, we should send the connection to a central coordinating goroutine,
		// which will decide how we respond,
		// and whether the connection should be promoted to the active view.
		if len(pc.joinAddr) > 0 {
			n.log.Info("TODO: handle the incoming join message")
		} else {
			n.log.Info("TODO: it must be a neighbor message?")
		}
	}
}

// handleIncomingDatagrams handles incoming datagrams for the given connection.
// It runs in a dedicated goroutine spawned from [(*Node).accept].
//
// We don't yet have datagram support but it will be added soon.
func (n *Node) handleIncomingDatagrams(ctx context.Context, conn *Connection) {
	defer n.wg.Done()

	log := conn.log.With("handler", "datagrams")

	for {
		b, err := conn.qConn.ReceiveDatagram(ctx)
		if err != nil {
			if ctx.Err() != nil {
				log.Info("Context finished while handling datagrams", "cause", context.Cause(ctx))
				return
			}

			// Otherwise not a context error.
			// Looking through the v0.49 quic-go code,
			// it looks like the only errors possible are datagrams disabled
			// (which we should not get since we asserted them enabled during node setup),
			// or the connection being closed explicitly.
			// I am pretty sure the close error will never be nil.
			// But if that is wrong, then we will need to separate handle
			// the returned byte slice being nil.
			log.Info("Error receiving datagram; goroutine stopping", "err", err)
			return
		}

		// TODO: actually do things with the datagram here.
		log.Info("Got datagram successfully", "msg", string(b))
	}
}

// DialPeer opens a QUIC connection to the given address,
// which is expected to be another DRAGON participant.
//
// Once the dial completes, in standard behavior,
// the client will send call [(*Connection.Join)] to join the network,
// or the client will send a Neighbor message to create a pairing.
func (n *Node) DialPeer(ctx context.Context, addr net.Addr) (*Connection, error) {
	qc, err := n.qt.Dial(ctx, addr, n.tlsConf, n.quicConf)
	if err != nil {
		return nil, fmt.Errorf("DialPeer: dial failed: %w", err)
	}

	return &Connection{
		log:   n.log.With("remote_addr", qc.RemoteAddr().String()),
		qConn: qc,

		node: n,
	}, nil
}
