package breathcast

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/bits"
	"sync"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle"
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/klauspost/reedsolomon"
)

// Protocol controls all the operations of the "breathcast" broadcasting protocol.
//
// The primary useful methods are [*Protocol.NewOrigination]
// to broadcast newly created data to peers in the active set,
// and [*Protocol.NewIncomingBroadcast] to handle an incoming broadcast.
//
// Originating a broadcast requires using [PrepareOrigination] first
// to split the original data into erasure-coded chunks and packets.
//
// To accept an incoming broadcast, the application layer must first
// accept an incoming stream from a connection,
// and then the application layer must confirm that the protocol ID matches.
// Then, since the application layer has mapped the stream's protocol ID
// to a particular protocol instance, it calls [*Protocol.ExtractStreamBroadcastID]
// to confirm which [*BroadcastOperation] the stream belongs to.
//
// At this point, the stream either belongs to a known BroadcastOperation,
// or it is not yet known.
// The application layer must then use [*Protocol.ExtractStreamApplicationHeader]
// to extract and parse the application-specific header on the stream.
// In addition to arbitrary application-specific data,
// that header must contain protocol-specific data
// required to populate the [IncomingBroadcastConfig].
type Protocol struct {
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
	IS   *incomingState
	Resp chan struct{}
}

// ProtocolConfig is the configuration passed to [NewProtocol].
type ProtocolConfig struct {
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
	// and it consumes space in chunk packets.
	BroadcastIDLength uint8
}

func NewProtocol(ctx context.Context, log *slog.Logger, cfg ProtocolConfig) *Protocol {
	if cfg.BroadcastIDLength == 0 {
		// It's plausible that there would be a use case
		// for saving the space required for broadcast IDs,
		// so for now we will allow zero with a warning.
		log.Warn(
			"Using broadcast ID length of zero prevents the network from having more than one distinct broadcast at a time",
		)
	}

	p := &Protocol{
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

func (p *Protocol) mainLoop(ctx context.Context, conns map[string]dconn.Conn) {
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

		case <-p.connChanges.Ready:
			// We have to keep our copy of the conns map updated,
			// as we hand out copies of it to new BroadcastOperation instances.
			cc := p.connChanges.Val
			if cc.Adding {
				conns[string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo)] = cc.Conn
			} else {
				delete(conns, string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo))
			}
		}
	}
}

func (p *Protocol) Wait() {
	<-p.mainLoopDone
	p.wg.Wait()
}

func (p *Protocol) handleNewBroadcastRequest(
	ctx context.Context,
	req newBroadcastRequest,
	conns map[string]dconn.Conn,
) {
	p.wg.Add(1)
	go req.Op.mainLoop(ctx, maps.Clone(conns), p.connChanges, &p.wg, req.IS)
	close(req.Resp)
}

type OriginationConfig struct {
	BroadcastID []byte

	AppHeader []byte
	Packets   [][]byte

	NData uint16

	// The size of the original data.
	// This differs from ChunkSize * NData,
	// as the final data packet may contain padding.
	TotalDataSize int

	// The size of the chunk in each packet.
	ChunkSize int
}

func (p *Protocol) NewOrigination(
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

		protocolID:  p.protocolID,
		broadcastID: cfg.BroadcastID,
		appHeader:   cfg.AppHeader,

		packets: cfg.Packets,

		nData:         cfg.NData,
		totalDataSize: cfg.TotalDataSize,
		chunkSize:     cfg.ChunkSize,

		dataReady: make(chan struct{}),

		// acceptBroadcastRequests and checkPacketRequests
		// can both be nil in this case.

		mainLoopDone: make(chan struct{}),
	}

	// Since we are originating, we have all the data already.
	close(op.dataReady)

	req := newBroadcastRequest{
		Op: op,
		// No incoming state value when we already have the data.
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

// IncomingBroadcastConfig is the config for [*Protocol.NewIncomingBroadcast].
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
	// proofs in packets consume less space.
	RootProofs [][]byte

	// The size of the underlying erasure-coded shards.
	// Necessary for reconstituting the original application data.
	ChunkSize uint16
}

func (p *Protocol) NewIncomingBroadcast(
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

		nData:   cfg.NData,
		nParity: cfg.NParity,

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

		protocolID:  p.protocolID,
		broadcastID: cfg.BroadcastID,
		appHeader:   cfg.AppHeader,

		// We will save the packets from incoming data,
		// so it's fine that the inner slices are all nil.
		packets: make([][]byte, cfg.NData+cfg.NParity),

		nData:         cfg.NData,
		totalDataSize: cfg.TotalDataSize,
		chunkSize:     int(cfg.ChunkSize),

		nChunks:        cfg.NData + cfg.NParity,
		hashSize:       cfg.HashSize,
		rootProofCount: len(cfg.RootProofs),

		dataReady: make(chan struct{}),

		acceptBroadcastRequests: make(chan acceptBroadcastRequest),
		checkPacketRequests:     make(chan checkPacketRequest),
		addPacketRequests:       make(chan addLeafRequest),

		mainLoopDone: make(chan struct{}),
	}

	req := newBroadcastRequest{
		Op:   op,
		IS:   is,
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

func cutoffTierFromRootProofsLen(proofsLen uint16) (tier uint8, ok bool) {
	if proofsLen == 0 {
		return 0, false
	}

	// The length must be of form (2^n)-1.
	// Therefore adding one makes it an even power of two.
	// And then we can use the property of (2^n) & ((2^n)-1) == 0
	// to check if the value is a power of two.
	if (proofsLen & (proofsLen + 1)) != 0 {
		return 0, false
	}

	// Otherwise, the +1 was indeed a power of two,
	// so we just need the number of bits required for proofsLen as-is.
	return uint8(bits.Len16(proofsLen) - 1), true
}

// ExtractStreamApplicationHeader extracts the application-provided header data
// from the given reader (which should be a QUIC stream).
// The extracted data is appended to the given dst slice,
// which is permitted to be nil.
//
// The stream is an origination stream created through [*Protocol.NewOrigination].
//
// The caller is responsible for setting any read deadlines.
//
// It is assumed that the caller has already consumed both
// the protocol ID byte matching [ProtocolConfig.ProtocolID],
// and the broadcast ID via [*Protocol.ExtractStreamBroadcastID].
func ExtractStreamApplicationHeader(r io.Reader, dst []byte) ([]byte, byte, error) {
	// First extract the app header length.
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, 0, fmt.Errorf(
			"failed to read app header length from origination protocol stream: %w",
			err,
		)
	}

	sz := binary.BigEndian.Uint16(buf[:])

	if cap(dst) >= int(sz) {
		dst = dst[:sz]
	} else {
		dst = make([]byte, sz)
	}

	if n, err := io.ReadFull(r, dst); err != nil {
		// Seems unlikely that dst would be useful to the caller on error,
		// but returning what we've read so far seems more proper anyway.
		return dst[:n], 0, fmt.Errorf(
			"failed to read header from origination protocol stream: %w",
			err,
		)
	}

	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return dst, 0, fmt.Errorf(
			"failed to read ratio byte from protocol stream: %w",
			err,
		)
	}

	return dst, buf[0], nil
}

// ExtractStreamBroadcastID extracts the broadcast ID
// from the given reader (which should be a QUIC stream).
// The extracted data is appended to the given dst slice,
// which is permitted to be nil.
//
// The stream is an origination stream created through [*Protocol.NewOrigination].
//
// The caller is responsible for setting any read deadlines.
//
// It is assumed that the caller has already consumed
// the protocol ID byte matching [ProtocolConfig.ProtocolID].
func (p *Protocol) ExtractStreamBroadcastID(r io.Reader, dst []byte) ([]byte, error) {
	if cap(dst) >= int(p.broadcastIDLength) {
		dst = dst[:p.broadcastIDLength]
	} else {
		dst = make([]byte, p.broadcastIDLength)
	}
	if _, err := io.ReadFull(r, dst); err != nil {
		return dst, fmt.Errorf(
			"failed to read broadcast ID from origination protocol stream: %w",
			err,
		)
	}

	return dst, nil
}

// ExtractPacketBroadcastID extracts the broadcast ID
// from the given raw packet bytes.
// Given the broadcast ID, the application can route the packet
// to the correct [RelayOperation].
//
// The caller must have already read the first byte of the input stream,
// confirming that the packet belongs to this protocol instance.
// The input must include that protocol identifier byte,
// so that the entire byte slice for the packet
// can be forwarded to other peers, if necessary,
// without rebuilding and reallocating the slice.
//
// If the packet is too short to contain a full broadcast ID,
// the returned slice will be nil.
//
// The returned slice is a subslice of the input,
// so retaining the return value will retain the input.
func (p *Protocol) ExtractPacketBroadcastID(raw []byte) []byte {
	if len(raw) == 0 {
		// Caller needs to protect against this.
		panic(errors.New(
			"BUG: input to ExtractPacketBroadcastID must not be empty",
		))
	}

	if raw[0] != p.protocolID {
		// Caller did not route message correctly.
		panic(fmt.Errorf(
			"BUG: first byte of packet was 0x%x, but it should have been the configured protocol ID 0x%x",
			raw[0], p.protocolID,
		))
	}

	if len(raw) < 1+int(p.broadcastIDLength) {
		return nil
	}

	return raw[1 : 1+p.broadcastIDLength]
}
