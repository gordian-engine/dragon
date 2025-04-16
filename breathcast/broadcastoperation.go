package breathcast

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/quic-go/quic-go"
)

// BroadcastOperation is a specific operation within a [Protocol2]
// that is responsible for all the network transfer related to a broadcast.
type BroadcastOperation struct {
	log *slog.Logger

	protocolID byte
	appHeader  []byte

	have      *bitset.BitSet // TODO: remove in favor of incoming state fields.
	datagrams [][]byte

	incoming *incomingState

	// Fields needed to parse datagrams.
	broadcastIDLength uint8
	nChunks           uint16
	hashSize          int
	rootProofCount    int

	// Channel that is closed when we have the entire set of datagrams
	// and the reconstituted data.
	dataReady chan struct{}

	acceptBroadcastRequests chan acceptBroadcastRequest2

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

type acceptBroadcastRequest2 struct {
	Conn   dconn.Conn
	Stream quic.Stream
	Resp   chan struct{}
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
	var protoHeader [4]byte
	protoHeader[0] = o.protocolID

	// As the broadcast originator, our "have ratio" is 100%.
	protoHeader[1] = 0xFF

	binary.BigEndian.PutUint16(protoHeader[2:], uint16(len(o.appHeader)))

	// Shortcut if we are originating.
	var isComplete bool
	select {
	case <-o.dataReady:
		isComplete = true
	default:
		// Incomplete.
	}

	if isComplete {
		o.initOrigination(ctx, conns)
		o.runOrigination(ctx, conns, connChanges, protoHeader)
		return
	}

	// We aren't originating, so we must be relaying.
	o.runRelay(ctx, conns, connChanges, protoHeader)
}

// runOrigination is the main loop when the operation
// has the full set of data.
func (o *BroadcastOperation) runOrigination(
	ctx context.Context,
	conns map[string]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
	protoHeader [4]byte,
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
	protoHeader [4]byte,
) *dchan.Multicast[dconn.Change] {
	cc := connChanges.Val
	if cc.Adding {
		conns[string(cc.Conn.Chain.Leaf.RawSubjectPublicKeyInfo)] = cc.Conn
		o.wg.Add(1)

		ob := &outgoingBroadcast{
			log: o.log.With("remote", cc.Conn.QUIC.RemoteAddr()),
			op:  o,
		}
		go ob.Run(ctx, cc.Conn.QUIC, protoHeader)
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
	protoHeader [4]byte,
) {
	for {
		select {
		case <-ctx.Done():
			// Don't bother logging close on this one.
			return

		case <-connChanges.Ready:
			connChanges = o.handleRelayConnChange(ctx, conns, connChanges, protoHeader)

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
	protoHeader [4]byte,
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
	minLen := 1 + int(o.broadcastIDLength) + 2 + 1 // At least 1 byte of proofs and raw chunk data.

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
	if !bytes.Equal(bID, raw[1:o.broadcastIDLength+1]) {
		panic(fmt.Errorf(
			"BUG: received datagram with incorrect broadcast ID: expected 0x%x, got 0x%x",
			bID, raw[1:o.broadcastIDLength+1],
		))
	}

	// The response depends on whether the index was valid in the first place,
	// and then on whether we already have the leaf for that index.
	idx := binary.BigEndian.Uint16(raw[1+int(o.broadcastIDLength) : 1+int(o.broadcastIDLength)+2])
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

			// Data has been reconstructed.
			// Notify any watchers.
			close(o.dataReady)
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

func (o *BroadcastOperation) initOrigination(
	ctx context.Context, conns map[string]dconn.Conn,
) {
	// We will send the app header directly,
	// but we also need a 4-byte protocol header.
	var protoHeader [4]byte
	protoHeader[0] = o.protocolID

	// As the broadcast originator, our "have ratio" is 100%.
	protoHeader[1] = 0xFF

	binary.BigEndian.PutUint16(protoHeader[2:], uint16(len(o.appHeader)))

	o.wg.Add(len(conns))
	for _, conn := range conns {
		ob := &outgoingBroadcast{
			log: o.log.With("remote", conn.QUIC.RemoteAddr()),
			op:  o,
		}
		go ob.Run(ctx, conn.QUIC, protoHeader)
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
	req := acceptBroadcastRequest2{
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
// by checking the broadcast ID via [*Protocol2.ExtractDatagramBroadcastID])
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
		o.broadcastIDLength,
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
