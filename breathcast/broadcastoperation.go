package breathcast

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/quic-go/quic-go"
)

// BroadcastOperation is a specific operation within a [Protocol]
// that is responsible for all the network transfer related to a broadcast.
type BroadcastOperation struct {
	log *slog.Logger

	protocolID  byte
	broadcastID []byte
	appHeader   []byte

	datagrams [][]byte

	// Needed for limiting the number of synchronous chunks sent.
	nData uint16

	// Needed for reconstituting data.
	totalDataSize int
	chunkSize     int

	// The incoming state is required to reconstruct the original data.
	// This field must be treated as volatile,
	// as it is set to nil once the data is reconstructed.
	// It is fine to retain a reference to the value,
	// so long as you are not accessing the field directly
	// outside of this type's methods.
	incoming *incomingState

	// Fields needed to parse datagrams.
	nChunks        uint16
	hashSize       int
	rootProofCount int

	// Channel that is closed when we have the entire set of datagrams
	// and the reconstituted data.
	dataReady chan struct{}

	acceptBroadcastRequests chan acceptBroadcastRequest

	// When handling an incoming datagram,
	// there is first a low-cost quick check through this channel,
	// so that contention on the main loop is minimized.
	checkDatagramRequests chan checkDatagramRequest

	// If the datagram was checked and the main loop still wants it,
	// the other goroutine adds the leaf data to a cloned partial tree,
	// and sends that tree and the parsed data back over this channel.
	addDatagramRequests chan addLeafRequest

	// The main loop isn't part of the wait group,
	// so that if we are adding goroutines through the main loop,
	// we don't have a race condition while waiting for the main loop.
	mainLoopDone chan struct{}
	wg           sync.WaitGroup
}

type acceptBroadcastRequest struct {
	Conn   dconn.Conn
	Stream quic.Stream
	Resp   chan struct{}
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

// checkDatagramResponseCode is the information that the operation main loop
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

// DataReady returns a channel that is closed
// when the operation has the entire broadcast data ready.
//
// For an BroadcastOperation created with [*Protocol.NewOrigination],
// the channel is closed at initialization.
// If the operation is created with [*Protocol.NewIncomingBroadcast],
// the channel is closed once the operation receives sufficient data from its peers.
func (o *BroadcastOperation) DataReady() <-chan struct{} {
	return o.dataReady
}

// Data returns an io.Reader that reads the actual data for the broadcast.
//
// Calls to Read will block if the data is not ready.
// Cancel the given ctx argument to allow reads to unblock with error.
func (o *BroadcastOperation) Data(ctx context.Context) io.Reader {
	return &broadcastDataReader{
		ctx:    ctx,
		op:     o,
		toRead: o.totalDataSize,
	}
}

func (o *BroadcastOperation) mainLoop(
	ctx context.Context,
	conns map[string]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
	wg *sync.WaitGroup,
) {
	defer close(o.mainLoopDone)
	defer wg.Done()

	// We set up the protocol header once
	// in case we need it during a connection change.
	protoHeader := make([]byte, 1+len(o.broadcastID)+3)

	// First byte is the protocol ID.
	protoHeader[0] = o.protocolID

	// Then the broadcast ID.
	// This is fixed-length per protocol instance,
	// but it is only known at runtime.
	copy(protoHeader[1:1+len(o.broadcastID)], o.broadcastID)

	// Single-byte ratio hint.
	// As the broadcast originator, our "have ratio" is 100%.
	protoHeader[1+len(o.broadcastID)] = 0xFF

	// Final two bytes are the application header size.
	binary.BigEndian.PutUint16(protoHeader[len(protoHeader)-2:], uint16(len(o.appHeader)))

	// Shortcut if we are originating.
	var isComplete bool
	select {
	case <-o.dataReady:
		isComplete = true
	default:
		// Incomplete.
	}

	if isComplete {
		o.initOrigination(ctx, conns, protoHeader)
		o.runOrigination(ctx, conns, connChanges, protoHeader)
		return
	}

	// We aren't originating, so we must be relaying.
	o.runRelay(ctx, conns, connChanges)
}

// runOrigination is the main loop when the operation
// has the full set of data.
func (o *BroadcastOperation) runOrigination(
	ctx context.Context,
	conns map[string]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
	protoHeader []byte,
) {
	for {
		select {
		case <-ctx.Done():
			// Don't bother logging close on this one.
			return

		case <-connChanges.Ready:
			connChanges = o.handleOriginationConnChange(ctx, conns, connChanges, protoHeader)

		case req := <-o.acceptBroadcastRequests:
			// We have all the data so we don't need the incoming broadcast.
			_ = req
			panic("TODO: close incoming broadcast request")
		}
	}
}

func (o *BroadcastOperation) handleOriginationConnChange(
	ctx context.Context,
	conns map[string]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
	protoHeader []byte,
) *dchan.Multicast[dconn.Change] {
	cc := connChanges.Val
	if cc.Adding {
		conns[string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo)] = cc.Conn

		ob := &outgoingBroadcast{
			log: o.log.With("remote", cc.Conn.QUIC.RemoteAddr()),
			op:  o,
		}
		ob.RunBackground(ctx, cc.Conn.QUIC, protoHeader)
	} else {
		delete(conns, string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo))
		// TODO: do we need to stop the in-progress operations in this case?
	}

	return connChanges.Next
}

// runRelay is the main loop when the operation
// does not have the full set of data.
func (o *BroadcastOperation) runRelay(
	ctx context.Context,
	conns map[string]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
) {
	for {
		select {
		case <-ctx.Done():
			// Don't bother logging close on this one.
			return

		case <-connChanges.Ready:
			connChanges = o.handleRelayConnChange(ctx, conns, connChanges)

		case req := <-o.acceptBroadcastRequests:
			ib := &incomingBroadcast{
				log: o.log.With("remote", req.Conn.QUIC.RemoteAddr()),
				op:  o,

				state: o.incoming,
			}
			ib.RunBackground(ctx, req.Stream)
			close(req.Resp)

		case req := <-o.checkDatagramRequests:
			o.handleCheckDatagramRequest(req)

		case req := <-o.addDatagramRequests:
			o.handleAddDatagramRequest(req)
		}
	}
}

func (o *BroadcastOperation) handleRelayConnChange(
	ctx context.Context,
	conns map[string]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
) *dchan.Multicast[dconn.Change] {
	cc := connChanges.Val
	if cc.Adding {
		conns[string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo)] = cc.Conn
		// TODO: if we are actively relaying,
		// we need to open an outbound relay to the new connection.
	} else {
		delete(conns, string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo))
		// TODO: do we need to stop the in-progress operations in this case?
	}

	return connChanges.Next
}

func (o *BroadcastOperation) handleCheckDatagramRequest(req checkDatagramRequest) {
	// The datagram layout is:
	//   - 1 byte, protocol ID
	//   - fixed-length broadcast ID
	//   - 2-byte (big-endian uint16) chunk ID
	//   - sequence of proofs (length implied via chunk ID)
	//   - raw chunk data
	bidLen := len(o.broadcastID)
	minLen := 1 + bidLen + 2 + 1 // At least 1 byte of proofs and raw chunk data.

	// Initial sanity checks.
	raw := req.Raw
	if len(raw) < minLen {
		panic(fmt.Errorf(
			"BUG: impossibly short datagram; length should have been at least %d, but got %d",
			len(raw), minLen,
		))
	}
	if raw[0] != o.protocolID {
		panic(fmt.Errorf(
			"BUG: tried to check datagram with invalid protocol ID 0x%x (only 0x%x is valid)",
			raw[0], o.protocolID,
		))
	}

	bID := o.incoming.broadcastID
	if !bytes.Equal(bID, raw[1:bidLen+1]) {
		panic(fmt.Errorf(
			"BUG: received datagram with incorrect broadcast ID: expected 0x%x, got 0x%x",
			bID, raw[1:bidLen+1],
		))
	}

	// The response depends on whether the index was valid in the first place,
	// and then on whether we already have the leaf for that index.
	idx := binary.BigEndian.Uint16(raw[1+bidLen : 1+bidLen+2])
	var resp checkDatagramResponse
	if idx >= (o.nChunks) {
		resp = checkDatagramResponse{
			Code: checkDatagramInvalidIndex,
			// No tree necessary.
		}
	} else if o.incoming.pt.HasLeaf(idx) {
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

		// TODO: extract to (*incomingState).GetTreeClone().
		if len(o.incoming.treeClones) == 0 {
			// No restored clones available, so allocate a new one.
			resp.Tree = o.incoming.pt.Clone()
		} else {
			// We have at least one old clone available for reuse.
			treeIdx := len(o.incoming.treeClones) - 1
			resp.Tree = o.incoming.treeClones[treeIdx]
			o.incoming.treeClones[treeIdx] = nil
			o.incoming.treeClones = o.incoming.treeClones[:treeIdx]

			o.incoming.pt.ResetClone(resp.Tree)
		}
	}

	// This response channel is created internally
	// and can be assumed to be buffered sufficiently.
	req.Resp <- resp
}

// handleAddDatagramRequest is called from the main loop.
func (o *BroadcastOperation) handleAddDatagramRequest(
	req addLeafRequest,
) {
	idx := req.Parsed.ChunkIndex
	i := o.incoming
	pt := i.pt
	leavesSoFar := pt.HaveLeaves().Count()
	if req.Add && leavesSoFar < uint(i.nData) && !pt.HaveLeaves().Test(uint(idx)) {
		// If there were two concurrent requests for the same index,
		// we don't need to go through merging the duplicate.
		pt.MergeFrom(req.Tree)

		// Now we copy the content to the encoder's shards.
		// This copy is not greatly memory-efficient,
		// since between those shards and the datagrams we hold,
		// we are storing two copies of the data;
		// but the encoder is supposed to see a significant throughput increase
		// when working with correctly memory-aligned shards,
		// so we assume for now that it's worth the tradeoff.
		i.shards[idx] = append(i.shards[idx], req.Parsed.Data...)

		// Also we have the raw datagram data that we can now retain.
		o.datagrams[idx] = req.RawDatagram

		// Now that the datagrams have been updated,
		// we can notify any observers that we have the datagram.
		i.addedLeafIndices.Set(uint(idx))
		i.addedLeafIndices = i.addedLeafIndices.Next

		leavesSoFar++
		if leavesSoFar >= uint(i.nData) {
			// TODO: need to check that we haven't reconstructed already.
			// If we get an extra shard concurrently with the last one,
			// we currently would double-close o.dataReady.

			// Possible earlier GC.
			i.treeClones = nil

			o.finishReconstruction()

			return
		}
	}

	// And hold on to the clone in case we can reuse it,
	// regardless of whether the datagram was addable.
	if leavesSoFar < uint(i.nData) {
		// TODO: we could discard the tree
		// if there would be more clones than missing chunks,
		// but that also risks re-allocating a new clone
		// if we are concurrently receiving datagrams.
		// Maybe we could allow the slice to be twice the size of the gap.
		i.treeClones = append(i.treeClones, req.Tree)
	} else {
		// We won't be using the tree clones anymore
		// now that we've reconstructed the data.
		// Drop the whole slice for earlier GC.
		i.treeClones = nil
	}
}

func (o *BroadcastOperation) Wait() {
	<-o.mainLoopDone
	o.wg.Wait()
}

func (o *BroadcastOperation) finishReconstruction() {
	i := o.incoming
	if err := i.enc.Reconstruct(i.shards); err != nil {
		// Something is extremely wrong if reconstruction fails.
		// We verified every Merkle proof along the way.
		// The panic message needs to be very detailed.
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "IMPOSSIBLE: reconstruction failed")
		for j, shard := range i.shards {
			fmt.Fprintf(&buf, "\n% 5d: %x", j, shard)
		}
		panic(errors.New(buf.String()))
	}

	// We have the raw data reconstructed now,
	// which means we have to complete the partial tree.
	haveLeaves := i.pt.HaveLeaves()
	missedCount := uint(i.nData) + uint(i.nParity) - haveLeaves.Count()

	missedLeaves := make([][]byte, 0, missedCount)
	for u, ok := haveLeaves.NextClear(0); ok; u, ok = haveLeaves.NextClear(u + 1) {
		missedLeaves = append(missedLeaves, i.shards[u])
	}

	c := i.pt.Complete(missedLeaves)
	o.restoreDatagrams(c)

	// Data has been reconstructed.
	// Notify any watchers.
	close(o.dataReady)
}

func (o *BroadcastOperation) restoreDatagrams(c cbmt.CompleteResult) {

	// All shards are the same size.
	// The last chunk likely includes padding.
	// In the future we may remove padding from the datagram,
	// although that will add complexity in a few places.
	// But it would be a slightly smaller allocation,
	// and fewer bytes across the network.
	shardSize := len(o.incoming.shards[0])

	// The base size of a datagram, excluding proofs.
	// Recall that proofs may be different lengths,
	// if the leaves are not a power of two
	// and if the missed leaves encounter both length classes.
	baseDatagramSize :=
		// 1-byte protocol header.
		1 +
			// Broadcast ID.
			len(o.broadcastID) +
			// uint16 for chunk index.
			2 +
			// Raw chunk data.
			shardSize

	var nHashes int
	for _, p := range c.Proofs {
		nHashes += len(p)
	}

	// One single backing allocation for all the new datagrams.
	// A single root object simplifies GC,
	// and the lifecycle of all datagrams is coupled together anyway.
	memSize := (baseDatagramSize * len(c.Proofs)) + (nHashes * o.hashSize)
	mem := make([]byte, memSize)

	haveLeaves := o.incoming.pt.HaveLeaves()
	var proofIdx, memIdx int
	for u, ok := haveLeaves.NextClear(0); ok; u, ok = haveLeaves.NextClear(u + 1) {
		dgStart := memIdx

		mem[memIdx] = o.protocolID
		memIdx++

		memIdx += copy(mem[memIdx:], o.broadcastID)

		binary.BigEndian.PutUint16(mem[memIdx:], uint16(u))
		memIdx += 2

		for _, p := range c.Proofs[proofIdx] {
			memIdx += copy(mem[memIdx:], p)
		}
		proofIdx++

		shardData := o.incoming.shards[u]
		memIdx += copy(mem[memIdx:], shardData)

		o.datagrams[u] = mem[dgStart:memIdx]
	}
}

func (o *BroadcastOperation) initOrigination(
	ctx context.Context, conns map[string]dconn.Conn, protoHeader []byte,
) {
	for _, conn := range conns {
		ob := &outgoingBroadcast{
			log: o.log.With("remote", conn.QUIC.RemoteAddr()),
			op:  o,
		}
		ob.RunBackground(ctx, conn.QUIC, protoHeader)
	}
}

// AcceptBroadcast accepts the incoming broadcast handshake,
// replying with a protocol-specific message indicating what shards
// the operation instance already has.
//
// The caller must have already verified the protocol ID
// and broadcast ID on the stream before passing it to this method.
func (o *BroadcastOperation) AcceptBroadcast(
	ctx context.Context,
	conn dconn.Conn,
	stream quic.Stream,
) error {
	req := acceptBroadcastRequest{
		Conn:   conn,
		Stream: stream,
		Resp:   make(chan struct{}),
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
func (o *BroadcastOperation) HandleDatagram(
	ctx context.Context,
	raw []byte,
) error {
	// Before trying to interact with the main loop,
	// see if the data has already been reconstructed.
	select {
	case <-o.dataReady:
		return nil
	default:
		// Keep going.
	}

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
		return o.attemptToAddDatagram(ctx, checkResp.Tree, raw)

	default:
		panic(fmt.Errorf(
			"TODO: handle check datagram response value %d", checkResp.Code,
		))
	}
}

func (o *BroadcastOperation) attemptToAddDatagram(
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
		uint8(len(o.broadcastID)),
		o.nChunks,
		uint(o.rootProofCount),
		o.hashSize,
	)
	err := t.AddLeaf(bd.ChunkIndex, bd.Data, bd.Proofs)

	req := addLeafRequest{
		Tree: t,
	}
	if err == nil {
		// Only set the field if we expect the main loop to retain it.
		// If there was an error, we don't want the datagram,
		// so it may be eligible for earlier GC.
		req.Add = true
		req.RawDatagram = raw
		req.Parsed = bd
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while sending add datagram request: %w",
			context.Cause(ctx),
		)
	case o.addDatagramRequests <- req:
		// Okay.
	}

	if err != nil {
		return fmt.Errorf("failed to add datagram: %w", err)
	}

	return nil
}
