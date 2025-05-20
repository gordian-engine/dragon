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
	"time"

	"github.com/gordian-engine/dragon/breathcast/internal/bci"
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

	// The raw packets, ready to be sent across the network.
	packets [][]byte

	// Needed for limiting the number of synchronous chunks sent.
	nData uint16

	// Needed for reconstituting data.
	totalDataSize int
	chunkSize     int

	// Fields needed to parse packets.
	nChunks        uint16
	hashSize       int
	rootProofCount int

	// Channel that is closed when we have the entire set of packets
	// and the reconstituted data.
	dataReady chan struct{}

	acceptBroadcastRequests chan acceptBroadcastRequest

	// When handling an incoming packet,
	// there is first a low-cost quick check through this channel,
	// so that contention on the main loop is minimized.
	checkPacketRequests chan checkPacketRequest

	// If the packet was checked and the main loop still wants it,
	// the other goroutine adds the leaf data to a cloned partial tree,
	// and sends that tree and the parsed data back over this channel.
	addPacketRequests chan addLeafRequest

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

type checkPacketRequest struct {
	Raw  []byte
	Resp chan checkPacketResponse
}

type checkPacketResponse struct {
	Code checkPacketResponseCode

	// If the caller needs to add a leaf,
	// this tree value will be non-nil.
	Tree *cbmt.PartialTree
}

// checkPacketResponseCode is the information that the operation main loop
// sends to the packet receiver,
// indicating what work needs to be offloaded from the main loop
// to the receiver's goroutine.
type checkPacketResponseCode uint8

const (
	// Nothing for zero.
	_ checkPacketResponseCode = iota

	// The index was out of bounds.
	checkPacketInvalidIndex

	// We already have the chunk ID.
	// The caller could choose whether to verify the proof anyway,
	// depending on the level of peer trust.
	checkPacketAlreadyHaveChunk

	// The chunk ID is in bounds and we don't have the chunk.
	checkPacketNeed
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
	RawPacket []byte

	// The parsed packet,
	// which contains the leaf index and the raw data content.
	Parsed bci.BroadcastPacket
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
	is *incomingState,
) {
	defer close(o.mainLoopDone)
	defer wg.Done()

	protoHeader := bci.NewProtocolHeader(
		o.protocolID,
		o.broadcastID,
		o.appHeader,
	)

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
		o.originationMainLoop(ctx, conns, connChanges, protoHeader)
		return
	}

	// We aren't originating, so we must be relaying.
	o.relayMainLoop(ctx, conns, connChanges, protoHeader, is)
}

// originationMainLoop is the main loop when the operation
// has the full set of data.
func (o *BroadcastOperation) originationMainLoop(
	ctx context.Context,
	conns map[string]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
	protoHeader bci.ProtocolHeader,
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

// runOrigination starts background routines to handle
// an outgoing broadcast while o has the full set of data.
func (o *BroadcastOperation) runOrigination(
	ctx context.Context,
	log *slog.Logger,
	conn quic.Connection,
	protoHeader bci.ProtocolHeader,
) {
	bci.RunOrigination(
		ctx,
		log,
		bci.OriginationConfig{
			WG:             &o.wg,
			Conn:           conn,
			ProtocolHeader: protoHeader,
			AppHeader:      o.appHeader,
			Packets:        o.packets,
			NData:          o.nData,
		},
	)
}

func (o *BroadcastOperation) handleOriginationConnChange(
	ctx context.Context,
	conns map[string]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
	protoHeader bci.ProtocolHeader,
) *dchan.Multicast[dconn.Change] {
	cc := connChanges.Val
	if cc.Adding {
		conns[string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo)] = cc.Conn

		o.runOrigination(
			ctx,
			o.log.With(
				"btype", "outgoing_broadcast",
				"remote", cc.Conn.QUIC.RemoteAddr(),
			),
			cc.Conn.QUIC,
			protoHeader,
		)
	} else {
		delete(conns, string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo))
		// TODO: do we need to stop the in-progress operations in this case?
	}

	return connChanges.Next
}

// runAcceptBroadcast starts background goroutines to handle
// accepting an incoming broadcast while o has less than full data.
func (o *BroadcastOperation) runAcceptBroadcast(
	ctx context.Context,
	log *slog.Logger,
	s quic.Stream,
	is *incomingState,
) {
	bci.RunAcceptBroadcast(
		ctx,
		log,
		bci.AcceptBroadcastConfig{
			WG: &o.wg,

			Stream: s,
			PacketDecoder: bci.NewPacketDecoder(
				o.protocolID,
				o.broadcastID,
				uint(o.rootProofCount),
				o.hashSize,
				uint16(o.chunkSize), // TODO: o.chunkSize is an int. Is uint16 too restrictive?
			),
			PacketHandler: o,

			InitialHaveLeaves: is.pt.HaveLeaves().Clone(),
			AddedLeaves:       is.addedLeafIndices,

			// TODO: should be configurable.
			BitsetSendPeriod: 2 * time.Millisecond,

			DataReady: o.dataReady,
		},
	)
}

// relayMainLoop is the main loop when the operation
// does not have the full set of data.
func (o *BroadcastOperation) relayMainLoop(
	ctx context.Context,
	conns map[string]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
	protoHeader bci.ProtocolHeader,
	is *incomingState,
) {
	for {
		select {
		case <-ctx.Done():
			// Don't bother logging close on this one.
			return

		case <-connChanges.Ready:
			connChanges = o.handleRelayConnChange(ctx, conns, connChanges, protoHeader, is)

		case req := <-o.acceptBroadcastRequests:
			o.runAcceptBroadcast(
				ctx,
				o.log.With(
					"btype", "incoming",
					"remote", req.Conn.QUIC.RemoteAddr(),
				),
				req.Stream,
				is,
			)
			close(req.Resp)

		case req := <-o.checkPacketRequests:
			o.handleCheckPacketRequest(req, is)

		case req := <-o.addPacketRequests:
			o.handleAddPacketRequest(req, is)
		}
	}
}

func (o *BroadcastOperation) handleRelayConnChange(
	ctx context.Context,
	conns map[string]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
	protoHeader bci.ProtocolHeader,
	is *incomingState,
) *dchan.Multicast[dconn.Change] {
	cc := connChanges.Val
	if cc.Adding {
		conns[string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo)] = cc.Conn

		bci.RunOutgoingRelay(
			ctx,
			o.log.With(
				"btype", "outgoing_relay",
				"remote", cc.Conn.QUIC.RemoteAddr(),
			),
			bci.OutgoingRelayConfig{
				WG:                  &o.wg,
				Conn:                cc.Conn.QUIC,
				ProtocolHeader:      protoHeader,
				AppHeader:           o.appHeader,
				Packets:             o.packets,
				InitialHavePackets:  is.pt.HaveLeaves().Clone(),
				NewAvailablePackets: is.addedLeafIndices,
				DataReady:           o.dataReady,
				NData:               o.nData,
				NParity:             o.nChunks - o.nData,
			},
		)
	} else {
		delete(conns, string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo))
		// TODO: do we need to stop the in-progress operations in this case?
	}

	return connChanges.Next
}

func (o *BroadcastOperation) handleCheckPacketRequest(
	req checkPacketRequest,
	is *incomingState,
) {
	// The packet layout is:
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
			"BUG: impossibly short packet; length should have been at least %d, but got %d",
			len(raw), minLen,
		))
	}
	if raw[0] != o.protocolID {
		panic(fmt.Errorf(
			"BUG: tried to check packet with invalid protocol ID 0x%x (only 0x%x is valid)",
			raw[0], o.protocolID,
		))
	}

	bID := o.broadcastID
	if !bytes.Equal(bID, raw[1:bidLen+1]) {
		panic(fmt.Errorf(
			"BUG: received packet with incorrect broadcast ID: expected 0x%x, got 0x%x",
			bID, raw[1:bidLen+1],
		))
	}

	// The response depends on whether the index was valid in the first place,
	// and then on whether we already have the leaf for that index.
	idx := binary.BigEndian.Uint16(raw[1+bidLen : 1+bidLen+2])
	var resp checkPacketResponse
	if idx >= (o.nChunks) {
		resp = checkPacketResponse{
			Code: checkPacketInvalidIndex,
			// No tree necessary.
		}
	} else if is.pt.HasLeaf(idx) {
		resp = checkPacketResponse{
			Code: checkPacketAlreadyHaveChunk,
			// Not sending a tree value back here,
			// but we could send back the expected hash of the chunk
			// so the worker can confirm its correctness.
		}
	} else {
		resp = checkPacketResponse{
			Code: checkPacketNeed,
		}

		// TODO: extract to (*incomingState).GetTreeClone().
		if len(is.treeClones) == 0 {
			// No restored clones available, so allocate a new one.
			resp.Tree = is.pt.Clone()
		} else {
			// We have at least one old clone available for reuse.
			treeIdx := len(is.treeClones) - 1
			resp.Tree = is.treeClones[treeIdx]
			is.treeClones[treeIdx] = nil
			is.treeClones = is.treeClones[:treeIdx]

			is.pt.ResetClone(resp.Tree)
		}
	}

	// This response channel is created internally
	// and can be assumed to be buffered sufficiently.
	req.Resp <- resp
}

// handleAddPacketRequest is called from the main loop.
func (o *BroadcastOperation) handleAddPacketRequest(
	req addLeafRequest,
	is *incomingState,
) {
	idx := req.Parsed.ChunkIndex
	pt := is.pt
	leavesSoFar := pt.HaveLeaves().Count()
	if req.Add && leavesSoFar < uint(is.nData) && !pt.HaveLeaves().Test(uint(idx)) {
		// If there were two concurrent requests for the same index,
		// we don't need to go through merging the duplicate.
		pt.MergeFrom(req.Tree)

		// Now we copy the content to the encoder's shards.
		// This copy is not greatly memory-efficient,
		// since between those shards and the packets we hold,
		// we are storing two copies of the data;
		// but the encoder is supposed to see a significant throughput increase
		// when working with correctly memory-aligned shards,
		// so we assume for now that it's worth the tradeoff.
		is.shards[idx] = append(is.shards[idx], req.Parsed.Data...)

		// Also we have the raw packet data that we can now retain.
		o.packets[idx] = req.RawPacket

		// Now that the packets have been updated,
		// we can notify any observers that we have the packet.
		is.addedLeafIndices.Set(uint(idx))
		is.addedLeafIndices = is.addedLeafIndices.Next

		leavesSoFar++
		if leavesSoFar >= uint(is.nData) {
			// TODO: need to check that we haven't reconstructed already.
			// If we get an extra shard concurrently with the last one,
			// we currently would double-close o.dataReady.

			// Possible earlier GC.
			is.treeClones = nil

			o.finishReconstruction(is)

			return
		}
	}

	// And hold on to the clone in case we can reuse it,
	// regardless of whether the packet was addable.
	if leavesSoFar < uint(is.nData) {
		// TODO: we could discard the tree
		// if there would be more clones than missing chunks,
		// but that also risks re-allocating a new clone
		// if we are concurrently receiving packets.
		// Maybe we could allow the slice to be twice the size of the gap.
		is.treeClones = append(is.treeClones, req.Tree)
	} else {
		// We won't be using the tree clones anymore
		// now that we've reconstructed the data.
		// Drop the whole slice for earlier GC.
		is.treeClones = nil
	}
}

func (o *BroadcastOperation) Wait() {
	<-o.mainLoopDone
	o.wg.Wait()
}

func (o *BroadcastOperation) finishReconstruction(is *incomingState) {
	if err := is.enc.Reconstruct(is.shards); err != nil {
		// Something is extremely wrong if reconstruction fails.
		// We verified every Merkle proof along the way.
		// The panic message needs to be very detailed.
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "IMPOSSIBLE: reconstruction failed")
		for j, shard := range is.shards {
			fmt.Fprintf(&buf, "\n% 5d: %x", j, shard)
		}
		panic(errors.New(buf.String()))
	}

	// We have the raw data reconstructed now,
	// which means we have to complete the partial tree.
	haveLeaves := is.pt.HaveLeaves()
	missedCount := uint(is.nData) + uint(is.nParity) - haveLeaves.Count()

	missedLeaves := make([][]byte, 0, missedCount)
	for u, ok := haveLeaves.NextClear(0); ok; u, ok = haveLeaves.NextClear(u + 1) {
		missedLeaves = append(missedLeaves, is.shards[u])
	}

	c := is.pt.Complete(missedLeaves)
	o.restorePackets(c, is)

	// Data has been reconstructed.
	// Notify any watchers.
	close(o.dataReady)
}

func (o *BroadcastOperation) restorePackets(
	c cbmt.CompleteResult,
	is *incomingState,
) {
	// All shards are the same size.
	// The last chunk likely includes padding.
	// In the future we may remove padding from the packets,
	// although that will add complexity in a few places.
	// But it would be a slightly smaller allocation,
	// and fewer bytes across the network.
	shardSize := len(is.shards[0])

	// The base size of a packet, excluding proofs.
	// Recall that proofs may be different lengths,
	// if the leaves are not a power of two
	// and if the missed leaves encounter both length classes.
	basePacketSize :=
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

	// One single backing allocation for all the new packets.
	// A single root object simplifies GC,
	// and the lifecycle of all packets is coupled together anyway.
	memSize := (basePacketSize * len(c.Proofs)) + (nHashes * o.hashSize)
	mem := make([]byte, memSize)

	haveLeaves := is.pt.HaveLeaves()
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

		shardData := is.shards[u]
		memIdx += copy(mem[memIdx:], shardData)

		o.packets[u] = mem[dgStart:memIdx]
	}
}

func (o *BroadcastOperation) initOrigination(
	ctx context.Context, conns map[string]dconn.Conn, protoHeader bci.ProtocolHeader,
) {
	for _, conn := range conns {
		o.runOrigination(
			ctx,
			o.log.With(
				"btype", "outgoing_broadcast",
				"remote", conn.QUIC.RemoteAddr(),
			),
			conn.QUIC,
			protoHeader,
		)
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
	if o.acceptBroadcastRequests == nil {
		// Running in origination mode.
		// We can simply close the given stream.
		stream.CancelRead(bci.GotFullDataErrorCode)
		_ = stream.Close()
		stream.CancelWrite(bci.GotFullDataErrorCode)

		// TODO: is nil most appropriate here,
		// or should we have a particular error type?
		return nil
	}

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

// HandlePacket parses the given packet
// (which must have already been confirmed to belong to this operation
// by checking the broadcast ID via [*Protocol.ExtractPacketBroadcastID])
// and updates the internal state of the operation.
//
// If the raw packet is valid and if it is new to this operation,
// it is forwarded to any peers who do not have it yet.
func (o *BroadcastOperation) HandlePacket(
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

	checkRespCh := make(chan checkPacketResponse, 1)
	checkReq := checkPacketRequest{
		Raw:  raw,
		Resp: checkRespCh,
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while making check packet request: %w",
			context.Cause(ctx),
		)
	case o.checkPacketRequests <- checkReq:
		// Okay.
	}

	var checkResp checkPacketResponse
	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while awaiting check packet response: %w",
			context.Cause(ctx),
		)
	case checkResp = <-checkRespCh:
		// Okay.
	}

	switch checkResp.Code {
	case checkPacketInvalidIndex:
		panic("TODO: handle invalid index")
	case checkPacketAlreadyHaveChunk:
		// TODO: we could decide whether to verify the proof anyway.
		return nil

	case checkPacketNeed:
		return o.attemptToAddPacket(ctx, checkResp.Tree, raw)

	default:
		panic(fmt.Errorf(
			"TODO: handle check packet response value %d", checkResp.Code,
		))
	}
}

func (o *BroadcastOperation) attemptToAddPacket(
	ctx context.Context, t *cbmt.PartialTree, raw []byte,
) error {
	// The input tree here is a clone of the tree in the main loop.
	// We have to add the leaf to the clone,
	// and regardless of the outcome of adding the leaf,
	// we have to return the clone to the main loop
	// so it can be reused.

	// TODO: we need a length check here to ensure parsing does not panic.
	bd := bci.ParseBroadcastPacket(
		raw,
		uint8(len(o.broadcastID)),
		o.nChunks,
		uint(o.rootProofCount),
		o.hashSize,
	)

	req := addLeafRequest{
		Tree: t,
	}

	err := t.AddLeaf(bd.ChunkIndex, bd.Data, bd.Proofs)
	if err == nil {
		// Only set the field if we expect the main loop to retain it.
		// If there was an error, we don't want the packet,
		// so it may be eligible for earlier GC.
		req.Add = true
		req.RawPacket = raw
		req.Parsed = bd
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf(
			"context canceled while sending add packet request: %w",
			context.Cause(ctx),
		)
	case o.addPacketRequests <- req:
		// Okay.
	}

	// We had to send the request in either case,
	// at a minimum to return the tree for reuse.
	// But if we failed to add the leaf then this call fails too.
	if err != nil {
		return fmt.Errorf("failed to add packet: %w", err)
	}

	return nil
}
