package breathcast

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

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
// Note, the broadcast is created through a [*Protocol.Originate].
//
// Once the broadcast is accepted,
// the operation manages all communication with peers.
type RelayOperation struct {
	log *slog.Logger

	// The protocol that owns the operation,
	// so we can enter through its main loop.
	p *Protocol

	// The Merkle tree that we are reconstituting from peers.
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

	// Channel that is closed when the data has been reconstituted.
	dataReady chan struct{}

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

// DataReady returns a channel that is closed
// once the data has been reconstructed.
func (o *RelayOperation) DataReady() <-chan struct{} {
	return o.dataReady
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
	// Whether to attempt to merge the provided tree.
	Add bool

	// The cloned tree we populated.
	// If Add is true, then any new hashes in Tree
	// will get copied to the main partial tree instance.
	Tree *cbmt.PartialTree

	// The relay operation will retain a reference to this slice,
	// so that it can be directly sent to other peers.
	RawDatagram []byte

	// The parsed datagram,
	// which contains the leaf index and the raw data content.
	Parsed broadcastDatagram
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
	var shardsSoFar uint16

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
			o.handleCheckDatagramRequest(req)

		case req := <-o.addLeafRequests:
			idx := req.Parsed.ChunkIndex
			if req.Add && !o.pt.HaveLeaves().Test(uint(idx)) {
				// If there were two concurrent requests for the same index,
				// we don't need to go through merging the duplicate.
				o.pt.MergeFrom(req.Tree)

				// Immediately note the newly available datagram,
				// as this could unblock other goroutines and peers.
				o.newDatagrams.Set(incomingDatagram{
					Raw: req.RawDatagram,
					Idx: idx,
				})
				o.newDatagrams = o.newDatagrams.Next

				// Now we copy the content to the encoder's shards.
				// This copy is not greatly memory-efficient,
				// since between those shards and the datagrams we hold,
				// we are storing two copies of the data;
				// but the encoder is supposed to see a significant throughput increase
				// when working with correctly memory-aligned shards,
				// so we assume for now that it's worth the tradeoff.
				shards[idx] = append(shards[idx], req.Parsed.Data...)

				shardsSoFar++
				if shardsSoFar >= o.nData {
					// TODO: need to check that we haven't reconstructed already.
					// If we get an extra shard concurrently with the last one,
					// we currently would double-close o.dataReady.
					if err := o.enc.Reconstruct(shards); err != nil {
						// Something is extremely wrong if reconstruction fails.
						// We verified every Merkle proof along the way.
						// The panic message needs to be very detailed.
						var buf bytes.Buffer
						fmt.Fprintf(&buf, "IMPOSSIBLE: reconstruction failed")
						for i, shard := range shards {
							fmt.Fprintf(&buf, "\n% 5d: %x", i, shard)
						}
						panic(errors.New(buf.String()))
					}

					// Data has been reconstructed.
					// Notify any watchers.
					close(o.dataReady)
				}
			}

			// And hold on to the clone in case we can reuse it,
			// regardless of whether the datagram was addable.
			// TODO: discard the tree if there would be more clones than missing chunks.
			o.treeClones = append(o.treeClones, req.Tree)
		}
	}
}

func (o *RelayOperation) handleCheckDatagramRequest(req checkDatagramRequest) {
	// The datagram layout is:
	//   - 1 byte, protocol ID
	//   - arbitrary but fixed-length broadcast ID
	//   - 2-byte (big-endian uint16) chunk ID
	//   - sequence of proofs (length implied via chunk ID)
	//   - raw chunk data
	minLen := 1 + int(o.p.broadcastIDLength) + 2 + 1 // At least 1 byte of proofs and raw chunk data.

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

	// This response channel is created internally
	// and can be assumed to be buffered sufficiently.
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

	// TODO: we need a length check here to ensure parsing does not panic.
	bd := parseBroadcastDatagram(
		raw,
		o.p.broadcastIDLength,
		o.nData+o.nParity,
		uint(len(o.rootProof)),
		len(o.rootProof[0]),
	)
	err := t.AddLeaf(bd.ChunkIndex, bd.Data, bd.Proofs)

	req := addLeafRequest{
		Add:  err == nil,
		Tree: t,
	}
	if err == nil {
		// Only set the field if we expect the main loop to retain it.
		// If there was an error, we don't want the datagram,
		// so it may be eligible for earlier GC.
		req.RawDatagram = raw
		req.Parsed = bd
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
