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

	// Whether we have the entire set of datagrams
	// and the reconstituted data.
	isComplete bool

	acceptBroadcastRequests chan acceptBroadcastRequest2

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

	// Channel that is closed when the data has been reconstituted.
	dataReady chan struct{}
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

	// Shortcut if we are originating.
	if o.isComplete {
		o.initOrigination(ctx, conns)
		o.runOrigination(ctx, conns, connChanges)
		return
	}

	// We aren't originating, so we must be relaying.
	// TODO: o.initRelay(ctx, conns)
	o.runRelay(ctx, connChanges)

	panic("TODO: handle incomplete initial broadcast")
}

// runOrigination is the main loop when the operation
// has the full set of data.
func (o *BroadcastOperation) runOrigination(
	ctx context.Context,
	conns map[string]dconn.Conn,
	connChanges *dchan.Multicast[dconn.Change],
) {
	// We set up the protocol header once
	// in case we need it during a connection change.
	var protoHeader [4]byte
	protoHeader[0] = o.protocolID

	// As the broadcast originator, our "have ratio" is 100%.
	protoHeader[1] = 0xFF

	binary.BigEndian.PutUint16(protoHeader[2:], uint16(len(o.appHeader)))

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
	connChanges *dchan.Multicast[dconn.Change],
) {
	for {
		select {
		case <-ctx.Done():
			// Don't bother logging close on this one.
			return

		case <-connChanges.Ready:
			panic("TODO: handle conn change")

		case req := <-o.acceptBroadcastRequests:
			_ = req
			panic("TODO: accept incoming broadcast")
		}
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
