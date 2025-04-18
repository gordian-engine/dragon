package breathcast

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle"
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/klauspost/reedsolomon"
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

	NData uint16

	TotalDataSize int
	ChunkSize     int
}

func (p *Protocol2) NewOrigination(
	ctx context.Context,
	cfg OriginationConfig,
) (*BroadcastOperation, error) {
	if cfg.TotalDataSize == 0 {
		panic(errors.New(
			"BUG: NewOrigination requires TotalDataSize > 0 (got 0)",
		))
	}
	if cfg.ChunkSize == 0 {
		panic(errors.New(
			"BUG: NewOrigination requires ChunkSize > 0 (got 0)",
		))
	}

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

		datagrams: cfg.Datagrams,

		nData:         cfg.NData,
		totalDataSize: cfg.TotalDataSize,
		chunkSize:     cfg.ChunkSize,

		dataReady: make(chan struct{}),

		// acceptBroadcastRequests and checkDatagramRequests
		// can both be nil in this case.

		mainLoopDone: make(chan struct{}),
	}

	// Since we are originating, we have all the data already.
	close(op.dataReady)

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

// IncomingBroadcastConfig is the config for [*Protocol2.NewIncomingBroadcast].
type IncomingBroadcastConfig struct {
	// How to identify this particular broadcast operation.
	BroadcastID []byte

	// The application header,
	// so we can forward it directly to other peers.
	AppHeader []byte

	// Number of data and parity chunks.
	NData, NParity uint16

	// The size in bytes of the reconstructed data.
	TotalDataSize int

	// How to verify hashes of incoming chunks.
	Hasher    bcmerkle.Hasher
	HashSize  int
	HashNonce []byte

	// The root proofs extracted from the incoming application header.
	// More root proofs in the header means that
	// proofs in datagrams consume less space.
	RootProofs [][]byte

	// The size of the underlying erasure-coded shards.
	// Necessary for reconstituting the original application data.
	ChunkSize uint16
}

func (p *Protocol2) NewIncomingBroadcast(
	ctx context.Context,
	cfg IncomingBroadcastConfig,
) (*BroadcastOperation, error) {
	if cfg.TotalDataSize == 0 {
		panic(errors.New(
			"BUG: NewIncomingBroadcast requires TotalDataSize > 0 (got 0)",
		))
	}
	if cfg.ChunkSize == 0 {
		panic(errors.New(
			"BUG: NewIncomingBroadcast requires ChunkSize > 0 (got 0)",
		))
	}

	// Set up the incoming state value first.
	enc, err := reedsolomon.New(
		int(cfg.NData), int(cfg.NParity),
		reedsolomon.WithAutoGoroutines(int(cfg.ChunkSize)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create reed solomon encoder: %w", err)
	}

	tier, ok := cutoffTierFromRootProofsLen(uint16(len(cfg.RootProofs)))
	if !ok {
		return nil, fmt.Errorf("invalid root proof length %d", len(cfg.RootProofs))
	}
	pt := cbmt.NewPartialTree(cbmt.PartialTreeConfig{
		NLeaves: cfg.NData + cfg.NParity,

		Hasher:   cfg.Hasher,
		HashSize: cfg.HashSize,
		Nonce:    cfg.HashNonce,

		ProofCutoffTier: tier,

		RootProofs: cfg.RootProofs,
	})

	shards := reedsolomon.AllocAligned(
		int(cfg.NData)+int(cfg.NParity), int(cfg.ChunkSize),
	)
	for i := range shards {
		// The incoming state relies on unpopulated shards being zero-length.
		shards[i] = shards[i][:0]
	}

	is := &incomingState{
		pt: pt,

		broadcastID: cfg.BroadcastID,
		nData:       cfg.NData,
		nParity:     cfg.NParity,

		enc:    enc,
		shards: shards,

		rootProof: cfg.RootProofs,

		addedLeafIndices: dchan.NewMulticast[uint](),
	}

	op := &BroadcastOperation{
		log: p.log.With(
			"op", "broadcast",
			"bid", fmt.Sprintf("%x", cfg.BroadcastID), // TODO: dlog.Hex helper?
		),

		protocolID: p.protocolID,
		appHeader:  cfg.AppHeader,

		// We will save the datagrams from incoming data,
		// so it's fine that the inner slices are all nil.
		datagrams: make([][]byte, cfg.NData+cfg.NParity),

		nData:         cfg.NData,
		totalDataSize: cfg.TotalDataSize,
		chunkSize:     int(cfg.ChunkSize),

		broadcastIDLength: p.broadcastIDLength,
		nChunks:           cfg.NData + cfg.NParity,
		hashSize:          cfg.HashSize,
		rootProofCount:    len(cfg.RootProofs),

		incoming: is,

		dataReady: make(chan struct{}),

		acceptBroadcastRequests: make(chan acceptBroadcastRequest2),
		checkDatagramRequests:   make(chan checkDatagramRequest),
		addDatagramRequests:     make(chan addLeafRequest),

		mainLoopDone: make(chan struct{}),
	}

	req := newBroadcastRequest{
		Op:   op,
		Resp: make(chan struct{}),
	}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"context canceled while sending incoming broadcast request: %w",
			context.Cause(ctx),
		)
	case p.newBroadcastRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"context canceled while waiting for incoming broadcast response: %w",
			context.Cause(ctx),
		)
	case <-req.Resp:
		return req.Op, nil
	}
}
