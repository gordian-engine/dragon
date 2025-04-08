package breathcast

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/bits"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/klauspost/reedsolomon"
	"github.com/quic-go/quic-go"
)

// RelayOperation is the operation for accepting an incoming broadcast.
//
// Instances must be created through [*Protocol.CreateRelayOperation].
//
// The application owns management of any live relay operations,
// and the application is responsible for routing incoming streams
// to the [*RelayOperation.AcceptBroadcast] method.
type RelayOperation struct {
	log *slog.Logger

	// The protocol that owns the operation,
	// so we can enter through its main loop.
	p *Protocol

	pt *cbmt.PartialTree

	// We are currently using clones for splitting PartialTree work
	// to other goroutines.
	//
	// When the other goroutines finish with their clone,
	// the clone is appended to this list
	// so it can be reclaimed the next time we need a clone.
	treeClones []*cbmt.PartialTree

	broadcastID    []byte
	nData, nParity uint16

	enc reedsolomon.Encoder

	rootProof [][]byte

	acceptBroadcastRequests chan acceptBroadcastRequest

	// When datagrams are routed to relay operations,
	// they need to consult the main loop to decide what work needs to be done.
	checkDatagramRequests chan checkDatagramRequest

	// When a checkDatagramResponseCode indicates the leaf should be added,
	// the working goroutine must send the response back to the main loop.
	addLeafRequests chan addLeafRequest

	newDatagrams *dchan.Multicast[incomingDatagram]

	ackTimeout time.Duration

	workerWG sync.WaitGroup
}

type acceptBroadcastRequest struct {
	S    quic.Stream
	Resp chan struct{}
}

type checkDatagramRequest struct {
	Raw  []byte
	Resp chan checkDatagramResponse
}

type checkDatagramResponse struct {
	Code checkDatagramResponseCode

	// If the caller needs to add a leaf,
	// this tree value will be non-nil.
	Tree *cbmt.PartialTree
}

// addLeafRequest is an internal request occurring after
// attempting to add a leaf to a cloned partial tree.
// There is no response back from the main loop for this.
type addLeafRequest struct {
	Add  bool
	Tree *cbmt.PartialTree
}

// incomingDatagram is the raw data of a broadcast chunk datagram,
// and its chunk index.
//
// These are used in the [RelayOperation] so that [relayWorker] instances
// can follow datagram updates and forward them to the peers.
type incomingDatagram struct {
	Raw []byte
	Idx uint16
}

// checkDatagramResponseCode is the information that the protocol main loop
// sends to the datagram receiver,
// indicating what work needs to be offloaded from the main loop
// to the receiver's goroutine.
type checkDatagramResponseCode uint8

const (
	// Nothing for zero.
	_ checkDatagramResponseCode = iota

	// The index was out of bounds.
	checkDatagramInvalidIndex

	// We already have the chunk ID.
	// The caller could choose whether to verify the proof anyway,
	// depending on the level of peer trust.
	checkDatagramAlreadyHaveChunk

	// The chunk ID is in bounds and we don't have the chunk.
	checkDatagramNeed
)

func (o *RelayOperation) run(ctx context.Context, shards [][]byte) {
	// Assume that when we begin a relay operation, we have populated shards.
	// Note that we can't rely on the length of the shards,
	// as reedsolomon.AllocAligned sets the slices to non-zero length.
	have := bitset.New(uint(len(shards)))
	_ = have

	for {
		select {
		case <-ctx.Done():
			o.log.Info(
				"Stopping due to context cancellation",
				"cause", context.Cause(ctx),
			)
			return

		case req := <-o.acceptBroadcastRequests:
			// TODO: we need to invoke the worker differently depending on
			// how many shards we already have.
			//
			// No shards is the default, and a trivial, case.
			o.workerWG.Add(1)
			w := &relayWorker{
				log: o.log.With("broadcast_stream", req.S.StreamID()),

				op: o,
			}
			go w.AcceptBroadcastFromEmpty(ctx, req.S)
			close(req.Resp)

		case req := <-o.checkDatagramRequests:
			o.handleCheckDatagramRequest(ctx, req)

		case req := <-o.addLeafRequests:
			if req.Add {
				o.pt.MergeFrom(req.Tree)
			}

			// And hold on to the clone in case we can reuse it.
			// TODO: discard the tree if we have too few missing shards remaining.
			o.treeClones = append(o.treeClones, req.Tree)
		}
	}
}

func (o *RelayOperation) handleCheckDatagramRequest(ctx context.Context, req checkDatagramRequest) {
	// The datagram layout is:
	//   - 1 byte, protocol ID
	//   - arbitrary but fixed-length broadcast ID
	//   - 2-byte (big-endian uint16) chunk ID
	//   - raw chunk data
	minLen := 1 + int(o.p.broadcastIDLength) + 2 + 1 // At least 1 byte of raw chunk data.

	// Initial sanity checks.
	raw := req.Raw
	if len(raw) < minLen {
		panic(fmt.Errorf(
			"BUG: impossibly short datagram; length should have been at least %d, but got %d",
			len(raw), minLen,
		))
	}
	if raw[0] != o.p.protocolID {
		panic(fmt.Errorf(
			"BUG: tried to check datagram with invalid protocol ID 0x%x (only 0x%x is valid)",
			raw[0], o.p.protocolID,
		))
	}
	if !bytes.Equal(raw[1:o.p.broadcastIDLength+1], o.broadcastID) {
		panic(fmt.Errorf(
			"BUG: received datagram with incorrect broadcast ID: expected 0x%x, got 0x%x",
			o.broadcastID, raw[1:o.p.broadcastIDLength+1],
		))
	}

	// The response depends on whether the index was valid in the first place,
	// and then on whether we already have the leaf for that index.
	idx := binary.BigEndian.Uint16(raw[1+int(o.p.broadcastIDLength) : 1+int(o.p.broadcastIDLength)+2])
	var resp checkDatagramResponse
	if idx >= (o.nData + o.nParity) {
		resp = checkDatagramResponse{
			Code: checkDatagramInvalidIndex,
			// No tree necessary.
		}
	} else if o.pt.HasLeaf(idx) {
		resp = checkDatagramResponse{
			Code: checkDatagramAlreadyHaveChunk,
			// Not sending a tree value back here,
			// but we could send back the expected hash of the chunk
			// so the worker can confirm its correctness.
		}
	} else {
		resp = checkDatagramResponse{
			Code: checkDatagramNeed,
		}

		if len(o.treeClones) == 0 {
			// No restored clones available, so allocate a new one.
			resp.Tree = o.pt.Clone()
		} else {
			// We have at least one old clone available for reuse.
			treeIdx := len(o.treeClones) - 1
			resp.Tree = o.treeClones[treeIdx]
			o.treeClones[treeIdx] = nil
			o.treeClones = o.treeClones[:treeIdx]

			o.pt.ResetClone(resp.Tree)
		}
	}

	req.Resp <- resp
}

// AcceptBroadcast accepts the incoming broadcast handshake,
// replying with a protocol-specific message indicating what shards
// the operation instance already has.
func (o *RelayOperation) AcceptBroadcast(ctx context.Context, s quic.Stream) error {
	req := acceptBroadcastRequest{
		S:    s,
		Resp: make(chan struct{}),
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while making request to accept broadcast: %w",
			context.Cause(ctx),
		)
	case o.acceptBroadcastRequests <- req:
		// Okay.
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while waiting for response to accept broadcast: %w",
			context.Cause(ctx),
		)
	case <-req.Resp:
		return nil
	}
}

// HandleDatagram parses the given datagram
// (which must have already been confirmed to belong to this operation
// by checking the broadcast ID via [*Protocol.ExtractDatagramBroadcastID])
// and updates the internal state of the operation.
//
// If the raw datagram is valid and if it is new to this operation,
// it is forwarded to any peers who may not have it yet.
func (o *RelayOperation) HandleDatagram(
	ctx context.Context,
	raw []byte,
) error {
	// This is a two-phase operation with the operation's main loop.
	// First, we pass the entire raw slice to the main loop.
	// The main loop inspects the chunk ID to determine if the ID is valid
	// and whether the chunk is new or preexisting information.
	// That check is fast, and it minimizes main loop contention.
	//
	// Then, depending on the main loop's judgement,
	// we do any heavy lifting in this separate goroutine.

	checkRespCh := make(chan checkDatagramResponse, 1)
	checkReq := checkDatagramRequest{
		Raw:  raw,
		Resp: checkRespCh,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while making check datagram request: %w",
			context.Cause(ctx),
		)
	case o.checkDatagramRequests <- checkReq:
		// Okay.
	}

	var checkResp checkDatagramResponse
	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while awaiting check datagram response: %w",
			context.Cause(ctx),
		)
	case checkResp = <-checkRespCh:
		// Okay.
	}

	switch checkResp.Code {
	case checkDatagramInvalidIndex:
		panic("TODO: handle invalid index")
	case checkDatagramAlreadyHaveChunk:
		// TODO: we could decide whether to verify the proof anyway.
		return nil

	case checkDatagramNeed:
		return o.attemptToAddLeaf(ctx, checkResp.Tree, raw)

	default:
		panic(fmt.Errorf(
			"TODO: handle check datagram response value %d", checkResp.Code,
		))
	}
}

func (o *RelayOperation) attemptToAddLeaf(
	ctx context.Context, t *cbmt.PartialTree, raw []byte,
) error {
	// The input tree here is a clone of the tree in the main loop.
	// We have to add the leaf to the clone,
	// and regardless of the outcome of adding the leaf,
	// we have to return the clone to the main loop
	// so it can be reused.

	// First we have to extract the leaf index.
	idxOffset := 1 + int(o.p.broadcastIDLength)
	leafIdx := binary.BigEndian.Uint16(raw[idxOffset : idxOffset+2])

	// Now, the number of proofs depends on whether this was a spillover leaf.

	nLeaves := o.nData + o.nParity
	treeHeight := bits.Len16(nLeaves)
	proofLen := treeHeight - bits.Len(uint(len(o.rootProof)))
	hasSpillover := nLeaves&(nLeaves-1) != 0
	if hasSpillover {
		// The leaves weren't a power of two.
		// Increment the tree height for spillover.
		treeHeight++
		// And if we are indexing a leaf that would be spillover,
		// increment the proof length for it too.
		spilloverCount := nLeaves - uint16(1<<(treeHeight-2))
		if leafIdx >= spilloverCount {
			proofLen++
		}
	}
	proofs := make([][]byte, proofLen)

	// We don't have a direct reference to the hash size on o.
	hashSize := len(o.rootProof[0])

	idxOffset += 2 // Move past the leaf index.
	for i := range proofs {
		proofs[i] = raw[idxOffset : idxOffset+hashSize]
		idxOffset += hashSize
	}

	content := raw[idxOffset:]
	err := t.AddLeaf(leafIdx, content, proofs)

	req := addLeafRequest{
		Add:  err == nil,
		Tree: t,
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while sending add leaf request: %w",
			context.Cause(ctx),
		)
	case o.addLeafRequests <- req:
		// Okay.
	}

	if err != nil {
		return fmt.Errorf("failed to add leaf: %w", err)
	}

	return nil
}

type RelayOperationConfig struct {
	// The ID for this specific broadcast operation being relayed.
	BroadcastID []byte

	// Arbitrary-length nonce required for the Merkle tree.
	Nonce []byte

	// The Merkle root proof
	// and possibly some of its descendants.
	RootProof [][]byte

	// The number of data and parity chunks;
	// required for proper Merkle tree reconstitution.
	NData, NParity uint16

	// Shard size is the size of the underlying erasure-coded shards.
	// Necessary for reconstituting the original application data.
	ShardSize uint16

	AckTimeout time.Duration
}
