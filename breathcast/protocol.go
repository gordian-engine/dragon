package breathcast

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/bits"
	"sync"
	"time"

	"github.com/gordian-engine/dragon/breathcast/bcmerkle/bcsha256"
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/klauspost/reedsolomon"
)

// Protocol controls all the operations of the "breathcast" broadcasting protocol.
type Protocol struct {
	log *slog.Logger

	connChanges       <-chan dconn.Change
	originateRequests chan originateRequest

	// Application-decided protocol ID to use for Breathcast.
	// Maybe we don't need this since the application
	// is supposed to route requests here?
	protocolID byte

	// All broadcast IDs within a protocol instance
	// must have the same length,
	// so that they can be uniformly decoded.
	// If the underlying header data is not uniform,
	// use a cryptographic hash of the underlying data.
	broadcastIDLength uint8

	// Tracks the mainLoop goroutine and the connection worker goroutines.
	wg sync.WaitGroup
}

// ProtocolConfig is the configuration passed to [NewProtocol].
type ProtocolConfig struct {
	// The initial connections to use.
	// The protocol will own this slice,
	// so the caller must not retain any references to it.
	InitialConnections []dconn.Conn

	// How to inform the protocol of connection changes.
	ConnectionChanges <-chan dconn.Change

	// The single header byte to be sent on outgoing streams.
	ProtocolID byte

	// The fixed length of broadcast identifiers.
	// This needs to be extracted from the origination header
	// and it consumes space in chunk datagrams.
	BroadcastIDLength uint8
}

// NewProtocol returns a new Protocol value with the given configuration.
// The given context controls the lifecycle of the Protocol.
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
		originateRequests: make(chan originateRequest),

		protocolID: cfg.ProtocolID,

		broadcastIDLength: cfg.BroadcastIDLength,
	}

	connWorkers := make(map[string]*connectionWorker, len(cfg.InitialConnections))
	for _, conn := range cfg.InitialConnections {
		wCtx, cancel := context.WithCancel(ctx)

		w := &connectionWorker{
			Ctx:    wCtx,
			Cancel: cancel,

			Log: p.log.With("conn", conn.QUIC.RemoteAddr().String()),

			QUIC:  conn.QUIC,
			Chain: conn.Chain,

			Originations: make(chan origination, 4), // Arbitrarily sized at 4.
		}

		p.wg.Add(1)
		go w.Work(&p.wg)
		connWorkers[string(conn.Chain.Leaf.RawSubjectPublicKeyInfo)] = w
	}

	p.wg.Add(1)
	go p.mainLoop(ctx, connWorkers)

	return p
}

// Wait blocks until all of p's background work has finished.
// The background work will begin stopping once the context
// passed to [NewProtocol] is canceled.
func (p *Protocol) Wait() {
	p.wg.Wait()
}

func (p *Protocol) mainLoop(ctx context.Context, connWorkers map[string]*connectionWorker) {
	defer p.wg.Done()

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

		case change := <-p.connChanges:
			key := string(change.Conn.Chain.Leaf.RawSubjectPublicKeyInfo)
			w, have := connWorkers[key]

			if change.Adding {
				if have {
					panic(fmt.Errorf(
						"BUG: attempted to add identical leaf certificate %q twice", key,
					))
				}

				wCtx, cancel := context.WithCancel(ctx)
				w := &connectionWorker{
					Ctx:    wCtx,
					Cancel: cancel,

					Log: p.log.With("conn", change.Conn.QUIC.RemoteAddr().String()),

					QUIC:  change.Conn.QUIC,
					Chain: change.Conn.Chain,

					Originations: make(chan origination, 4), // Arbitrarily sized at 4.
				}

				p.wg.Add(1)
				go w.Work(&p.wg)
				connWorkers[key] = w
			} else {
				if !have {
					panic(fmt.Errorf(
						"BUG: attempted to remove leaf certificate %q that did not exist", key,
					))
				}

				w.Cancel()
				delete(connWorkers, key)
			}

		case req := <-p.originateRequests:
			// Fan out this request to every connection worker.
			// This blocks the main loop,
			// which seems necessary since we retain the only copy
			// of the connection worker map.
			for _, cw := range connWorkers {
				select {
				case cw.Originations <- req.O:
					// Okay.
				default:
					// We could possibly just drop the connection here.
					// Or we could collect the blocked ones in a slice and retry one more time.
					// Not very clear what the best solution is, yet.
					panic(fmt.Errorf(
						"TODO: decide how to handle blocked send on origination work",
					))
				}
			}

			close(req.Resp)
		}
	}
}

// OriginateTask is the result of calling [*Protocol.Originate].
type OriginateTask struct {
	// TODO: what details should this expose?
}

// Originate begins a broadcast to all peers in the active view.
// headerData is an application-specific encoding.
//
// The header data must contain details for the partial Merkle tree,
// the number of data and parity chunks,
// the chunk size, and the full reconstructed data size.
// It may contain any other application-specific data.
//
// The header is sent over a reliable QUIC stream,
// before the fragments are sent over unreliable datagrams,
// so the header data should be concise within reason.
//
// The returned task will remain active until the context is finished.
// That is, the protocol will send the origination to any new connections
// while the task is still active.
//
// The caller should use [context.WithCancelCause] with a TBD error
// in order to signal a proper finish of an originate task,
// distinct from other interrupt-style context cancellations.
func (p *Protocol) Originate(
	ctx context.Context,
	headerData []byte,
	dataChunks [][]byte,
	parityChunks [][]byte,
) (OriginateTask, error) {
	t := OriginateTask{
		// TODO: still unclear what fields belong in this type.
	}

	if len(headerData) > (1<<16)-1 {
		return t, fmt.Errorf(
			"headerData too long: %d exceeds limit of %d",
			len(headerData), (1<<16)-1,
		)
	}

	resp := make(chan struct{})
	req := originateRequest{
		O: origination{
			Ctx: ctx,

			// TODO: these should be configurable.
			OpenStreamTimeout:     50 * time.Millisecond,
			SendHeaderTimeout:     50 * time.Millisecond,
			ReceiveAckTimeout:     50 * time.Millisecond,
			SendCompletionTimeout: 25 * time.Millisecond,

			ProtocolID: p.protocolID,

			Header:       headerData,
			DataChunks:   dataChunks,
			ParityChunks: parityChunks,
		},
		Resp: resp,
	}

	select {
	case <-ctx.Done():
		return t, fmt.Errorf(
			"context canceled while sending origination request: %w",
			context.Cause(ctx),
		)
	case p.originateRequests <- req:
		return t, nil
	}
}

type origination struct {
	Ctx context.Context

	OpenStreamTimeout     time.Duration
	SendHeaderTimeout     time.Duration
	ReceiveAckTimeout     time.Duration
	SendCompletionTimeout time.Duration

	ProtocolID byte

	Header       []byte
	DataChunks   [][]byte
	ParityChunks [][]byte
}

type originateRequest struct {
	O origination

	Resp chan struct{}
}

func (p *Protocol) CreateRelayOperation(
	createCtx, taskCtx context.Context,
	cfg RelayOperationConfig,
) (*RelayOperation, error) {
	enc, err := reedsolomon.New(
		int(cfg.NData), int(cfg.NParity),
		reedsolomon.WithAutoGoroutines(int(cfg.ShardSize)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create reed solomon encoder: %w", err)
	}

	shards := reedsolomon.AllocAligned(int(cfg.NData+cfg.NParity), int(cfg.ShardSize))

	if len(cfg.RootProof) > (1<<16)-1 {
		panic(fmt.Errorf(
			"BUG: root proofs length must fit into a uint16 (got length %d)",
			len(cfg.RootProof),
		))
	}

	cutoffTier, ok := cutoffTierFromRootProofsLen(uint16(len(cfg.RootProof)))
	if !ok {
		return nil, fmt.Errorf(
			"invalid root proof length %d: must be of form 2^n - 1",
			len(cfg.RootProof),
		)
	}

	t := &RelayOperation{
		log: p.log.With("op", "relay"),

		p: p,

		pt: cbmt.NewPartialTree(cbmt.PartialTreeConfig{
			NLeaves: cfg.NData + cfg.NParity,

			// TODO: configure these through RelayOperationConfig instead of hardcoding.
			Hasher:   bcsha256.Hasher{},
			HashSize: bcsha256.HashSize,

			Nonce: cfg.Nonce,

			ProofCutoffTier: cutoffTier,

			RootProofs: cfg.RootProof,
		}),

		enc: enc,

		broadcastID: cfg.BroadcastID,
		nData:       cfg.NData,
		nParity:     cfg.NParity,

		rootProof: cfg.RootProof,

		// All arbitrarily sized for now.
		acceptBroadcastRequests: make(chan acceptBroadcastRequest, 4),
		checkDatagramRequests:   make(chan checkDatagramRequest, 4),
		addLeafRequests:         make(chan addLeafRequest, 4),

		newDatagrams: dchan.NewMulticast[incomingDatagram](),

		ackTimeout: cfg.AckTimeout,
	}

	go t.run(taskCtx, shards)

	return t, nil
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

// ExtractBroadcastHeader extracts the application-provided header data
// from the given reader (which should be a QUIC stream).
// The extracted data is appended to the given dst slice,
// which is permitted to be nil.
//
// The caller is responsible for setting any read deadlines.
//
// It is assumed that the caller has already consumed
// the protocol ID byte matching [ProtocolConfig.ProtocolID].
func ExtractBroadcastHeader(r io.Reader, dst []byte) ([]byte, error) {
	// First extract the have ratio and the header length.
	var buf [3]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, fmt.Errorf(
			"failed to read ratio and header length from origination protocol stream: %w",
			err,
		)
	}

	if buf[0] != 0xff {
		panic(fmt.Errorf(
			"TODO: handle relayed broadcast (got ratio byte 0x%x)", buf[0],
		))
	}

	sz := binary.BigEndian.Uint16(buf[1:])

	if cap(dst) >= int(sz) {
		dst = dst[:sz]
	} else {
		dst = make([]byte, sz)
	}

	if n, err := io.ReadFull(r, dst); err != nil {
		// Seems unlikely that dst would be useful to the caller on error,
		// but returning what we've read so far seems more proper anyway.
		return dst[:n], fmt.Errorf(
			"failed to read header from origination protocol stream: %w",
			err,
		)
	}

	return dst, nil
}

// ExtractDatagramBroadcastID extracts the broadcast ID
// from the given raw datagram bytes.
// Given the broadcast ID, the application can route the datagram
// to the correct [RelayOperation].
//
// The caller must have already read the first byte of the input stream,
// confirming that the datagram belongs to this protocol instance.
// The input must include that protocol identifier byte,
// so that the entire byte slice for the datagram
// can be forwarded to other peers, if necessary,
// without rebuilding and reallocating the slice.
//
// If the datagram is too short to contain a full broadcast ID,
// both returned slice will be nil.
//
// The returned slice is a subslice of the input,
// so retaining the return value will retain the input.
func (p *Protocol) ExtractDatagramBroadcastID(raw []byte) []byte {
	if len(raw) == 0 {
		// Caller needs to protect against this.
		panic(errors.New(
			"BUG: input to ExtractDatagramBroadcastID must not be empty",
		))
	}

	if raw[0] != p.protocolID {
		// Caller did not route message correctly.
		panic(fmt.Errorf(
			"BUG: first byte of datagram was 0x%x, but it should have been the configured protocol ID 0x%x",
			raw[0], p.protocolID,
		))
	}

	if len(raw) < 1+int(p.broadcastIDLength) {
		return nil
	}

	return raw[1 : 1+p.broadcastIDLength]
}
