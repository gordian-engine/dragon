package breathcast

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
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

	enc reedsolomon.Encoder

	rootProof [][]byte

	acceptBroadcastRequests chan acceptBroadcastRequest

	// When datagrams are routed to relay operations,
	// they need to consult the main loop to decide what work needs to be done.
	checkDatagramRequests chan checkDatagramRequest

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

// incomingDatagram is the raw data of a broadcast chunk datagram,
// and its chunk index.
//
// These are used in the [RelayOperation] so that [relayWorker] instances
// can follow datagram updates and forward them to the peers.
type incomingDatagram struct {
	Raw []byte
	Idx uint16
}

// checkDatagramResponse is the information that the protocol main loop
// sends to the datagram receiver,
// indicating what work needs to be offloaded from the main loop
// to the receiver's goroutine.
type checkDatagramResponse uint8

const (
	// Nothing for zero.
	_ checkDatagramResponse = iota

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
		}
	}
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

	switch checkResp {
	case checkDatagramInvalidIndex:
		panic("TODO: handle invalid index")
	case checkDatagramAlreadyHaveChunk:
		// TODO: we could decide whether to verify the proof anyway.
		return nil

	case checkDatagramNeed:
		panic("TODO: verify proof and send back to main loop")

	default:
		panic(fmt.Errorf("TODO: handle check datagram response value %d", checkResp))
	}
}

type RelayOperationConfig struct {
	// The ID for this specific broadcast operation being relayed.
	BroadcastID []byte

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
