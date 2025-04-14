package breathcast

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
)

// Protocol2 is a revised implementation of [Protocol].
type Protocol2 struct {
	log *slog.Logger

	// Multicast for connection changes,
	// so that broadcast operations can observe it directly.
	connChanges  *dchan.Multicast[dconn.Change]
	currentConns []dconn.Conn

	newBroadcastRequests chan newBroadcastRequest

	// Application-decided protocol ID to use for Breathcast.
	// Necessary for outgoing streams.
	protocolID byte

	// All broadcast IDs within a protocol instance
	// must have the same length,
	// so that they can be uniformly decoded.
	// If the underlying header data is not uniform,
	// use a cryptographic hash of the underlying data.
	broadcastIDLength uint8

	// Separate from the wait group,
	// to avoid possible race condition when closing.
	mainLoopDone chan struct{}

	// Tracks the broadcast operations in progress.
	wg sync.WaitGroup
}

type newBroadcastRequest struct {
	Op   *BroadcastOperation
	Resp chan struct{}
}

// Protocol2Config is the configuration passed to [NewProtocol2].
type Protocol2Config struct {
	// The initial connections to use.
	// The protocol will own this slice,
	// so the caller must not retain any references to it.
	InitialConnections []dconn.Conn

	// How to inform the protocol of connection changes.
	// Using dchan.Multicast for this reduces the number of required goroutines,
	// at the cost of a heap-allocated linked list.
	ConnectionChanges *dchan.Multicast[dconn.Change]

	// The single protocol-identifying byte to be sent on outgoing streams.
	ProtocolID byte

	// The fixed length of broadcast identifiers.
	// The broadcast ID needs to be extracted from the origination header
	// and it consumes space in chunk datagrams.
	BroadcastIDLength uint8
}

func NewProtocol2(ctx context.Context, log *slog.Logger, cfg Protocol2Config) *Protocol2 {
	if cfg.BroadcastIDLength == 0 {
		// It's plausible that there would be a use case
		// for saving the space required for broadcast IDs,
		// so for now we will allow zero with a warning.
		log.Warn(
			"Using broadcast ID length of zero prevents the network from having more than one distinct broadcast at a time",
		)
	}

	p := &Protocol2{
		log: log,

		connChanges: cfg.ConnectionChanges,

		// Unbuffered since the caller blocks on it.
		newBroadcastRequests: make(chan newBroadcastRequest),

		protocolID: cfg.ProtocolID,

		broadcastIDLength: cfg.BroadcastIDLength,

		mainLoopDone: make(chan struct{}),
	}

	conns := make(map[string]dconn.Conn, len(cfg.InitialConnections))
	for _, c := range cfg.InitialConnections {
		conns[string(c.Chain.Leaf.RawSubjectPublicKeyInfo)] = c
	}

	go p.mainLoop(ctx, conns)

	return p
}

func (p *Protocol2) mainLoop(ctx context.Context, conns map[string]dconn.Conn) {
	defer close(p.mainLoopDone)

	for {
		select {
		case <-ctx.Done():
			p.log.Info(
				"Stopping due to context cancellation",
				"cause", context.Cause(ctx),
			)

			// We don't need to cancel any of the workers,
			// because all of their contexts were derived from this ctx.
			return

		case req := <-p.newBroadcastRequests:
			p.handleNewBroadcastRequest(ctx, req, conns)
		}
	}
}

func (p *Protocol2) Wait() {
	<-p.mainLoopDone
	p.wg.Wait()
}

func (p *Protocol2) handleNewBroadcastRequest(
	ctx context.Context,
	req newBroadcastRequest,
	conns map[string]dconn.Conn,
) {
	p.wg.Add(1)
	go req.Op.mainLoop(ctx, conns, p.connChanges, &p.wg)
	close(req.Resp)
}

type OriginationConfig struct {
	BroadcastID []byte

	AppHeader []byte
	Datagrams [][]byte
}

func (p *Protocol2) NewOrigination(
	ctx context.Context,
	cfg OriginationConfig,
) (*BroadcastOperation, error) {
	if len(cfg.AppHeader) > (1<<16)-1 {
		return nil, fmt.Errorf(
			"NewOrigination: OriginationConfig.AppHeader too long: %d exceeds limit of %d",
			len(cfg.AppHeader), (1<<16)-1,
		)
	}

	// Do as much allocating as we can on this goroutine,
	// so the main loop doesn't have to spend time in allocations.
	op := &BroadcastOperation{
		log: p.log.With(
			"op", "broadcast",
			"bid", fmt.Sprintf("%x", cfg.BroadcastID), // TODO: dlog.Hex helper?
		),

		protocolID: p.protocolID,
		appHeader:  cfg.AppHeader,

		datagrams:  cfg.Datagrams,
		isComplete: true,

		mainLoopDone: make(chan struct{}),
	}

	req := newBroadcastRequest{
		Op:   op,
		Resp: make(chan struct{}),
	}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"context canceled while sending origination request: %w",
			context.Cause(ctx),
		)
	case p.newBroadcastRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"context canceled while waiting for origination response: %w",
			context.Cause(ctx),
		)
	case <-req.Resp:
		return req.Op, nil
	}
}
