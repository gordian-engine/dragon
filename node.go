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

	// Determines the behavior of choosing to accept peer connections.
	PeerEvaluator deval.PeerEvaluator
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
	if !cfg.QUIC.EnableDatagrams {
		panic(errors.New("gblockdist.Node requires QUIC datagrams; set cfg.Quic.EnableDatagrams=true"))
	}

	if cfg.PeerEvaluator == nil {
		panic(errors.New("NodeConfig.PeerEvaluator may not be nil"))
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

	kCfg := dk.KernelConfig{
		PeerEvaluator: cfg.PeerEvaluator,
	}

	n := &Node{
		log: log,

		k: dk.NewKernel(ctx, log.With("node_sys", "kernel"), kCfg),

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
	n.k.Wait()
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

		ic := &inboundConnection{
			log:   n.log.With("remote_conn", qc.RemoteAddr().String()),
			qConn: qc,
		}
		ic.log.Info("Connection accepted")

		if err := ic.handleIncomingStreamHandshake(ctx); err != nil {
			ic.log.Info("Failed to handle incoming stream handshake", "err", err)

			if err := qc.CloseWithError(1, "TODO: REASON"); err != nil {
				ic.log.Debug("Failed to send close message to peer", "err", err)
			}

			continue
		}

		// The pending connection succeeded.
		if len(ic.joinAddr) > 0 {
			// TODO: this branch is way too long and needs to be extracted to its own method.

			peer := deval.Peer{
				TLS:        qc.ConnectionState().TLS,
				LocalAddr:  qc.LocalAddr(),
				RemoteAddr: qc.RemoteAddr(),
			}
			respCh := make(chan dk.JoinResponse, 1)
			req := dk.JoinRequest{
				Peer: peer,
				Resp: respCh,
			}

			select {
			case n.k.JoinRequests <- req:
				// Okay.
			case <-ctx.Done():
				n.log.Info("Accept loop quitting due to context cancellation during join request", "cause", context.Cause(ctx))
				return
			}

			select {
			case resp := <-respCh:
				// The kernel responded with the decision on what to do with the incoming join.
				if err := ic.handleJoinDecision(resp.Decision); err != nil {
					ic.log.Info(
						"Failed while handling join decision",
						"decision", resp.Decision,
						"err", err,
					)
					if err := qc.CloseWithError(1, "TODO: REASON"); err != nil {
						ic.log.Debug("Failed to send close message to peer", "err", err)
					}

					if cause := context.Cause(ctx); cause != nil {
						n.log.Info(
							"Accept loop quitting due to context cancellation while handling join decision",
							"cause", cause,
						)
						return
					}

					continue
				}

				// Since the inbound connection handled the join decision,
				// we either closed the connection and are discarding it,
				// or the connection has an outgoing neighbor request.

				if resp.Decision == dk.AcceptJoinDecision {
					// The kernel said to accept, so the incomingConnection wrapper
					// sent out a Neighbor request to the peer.
					//
					// We have to continue blocking while we wait for the neighbor reply,
					// so that we continue to consume one of the pending connection slots.
					ac := ic.AsAwaitingNeighborReply()
					if err := ac.AwaitNeighborReply(ctx); err != nil {
						ac.log.Info("Failed while waiting for neighbor reply", "err", err)

						if err := qc.CloseWithError(1, "TODO (AwaitNeighborReply)"); err != nil {
							ac.log.Debug("Failed to send close message to peer", "err", err)
						}

						continue
					}

					// We got the neighbor reply,
					// so now it is our turn to initialize the streams,
					// indicating our acknowledgement of the reply.
					if err := ac.FinishInitializingStreams(ctx); err != nil {
						ac.log.Info("Failed to finish initializing streams", "err", err)

						if err := qc.CloseWithError(1, "TODO (FinishInitializingStreams)"); err != nil {
							ac.log.Debug("Failed to send close message to peer", "err", err)
						}

						continue
					}

					// The streams are fully intialized,
					// so we can pass the connection to the kernel now.
					pResp := make(chan dk.NewPeeringResponse, 1)
					req := dk.NewPeeringRequest{
						QuicConn: qc,

						AdmissionStream:  ac.admissionStream,
						DisconnectStream: ac.disconnectStream,
						ShuffleStream:    ac.shuffleStream,

						Resp: pResp,
					}

					select {
					case <-ctx.Done():
						ac.log.Info(
							"Context cancelled while sending peering request to kernel",
							"cause", context.Cause(ctx),
						)
						return

					case n.k.NewPeeringRequests <- req:
						// Okay.
					}

					select {
					case <-ctx.Done():
						ac.log.Info(
							"Context cancelled while awaiting peering response from kernel",
							"cause", context.Cause(ctx),
						)
						return
					case resp := <-pResp:
						if resp.RejectReason != "" {
							// Last minute issue with adding the connection.
							if err := qc.CloseWithError(1, "TODO: peering rejected: "+resp.RejectReason); err != nil {
								ac.log.Debug("Failed to close connection", "err", err)
							}

							continue
						}

						// Otherwise it was accepted, and the Join is complete.
						continue
					}
				}

				continue
			case <-ctx.Done():
				n.log.Info("Accept loop quitting due to context cancellation during join response", "cause", context.Cause(ctx))
				return
			}

		} else {
			n.log.Info("TODO: it must be a neighbor message?")
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
	qc, err := n.qt.Dial(ctx, addr, n.tlsConf, n.quicConf)
	if err != nil {
		return nil, fmt.Errorf("DialPeer: dial failed: %w", err)
	}

	return &UnpeeredConnection{
		log:   n.log.With("remote_addr", qc.RemoteAddr().String()),
		qConn: qc,

		k: n.k,
	}, nil
}

func (n *Node) ActiveViewSize() int {
	return n.k.GetActiveViewSize()
}
