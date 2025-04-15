package breathcast

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"

	"github.com/bits-and-blooms/bitset"
	"github.com/gordian-engine/dragon/breathcast/internal/merkle/cbmt"
	"github.com/gordian-engine/dragon/dconn"
	"github.com/gordian-engine/dragon/internal/dchan"
	"github.com/klauspost/reedsolomon"
	"github.com/quic-go/quic-go"
)

// BroadcastOperation is a specific operation within a [Protocol2]
// that is responsible for all the network transfer related to a broadcast.
type BroadcastOperation struct {
	log *slog.Logger

	protocolID byte
	appHeader  []byte

	have      *bitset.BitSet
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

type incomingState struct {
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
			go ib.RunBackground(ctx, req.Stream)
			close(req.Resp)
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
