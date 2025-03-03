package dfanout

import (
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/internal/dmsg"
	"github.com/gordian-engine/dragon/internal/dprotoi"
	"github.com/quic-go/quic-go"
)

// Seed channels are "pre-work" channels,
// where the kernel can send a single value
// that will eventually fan out to the workers.
//
// If the kernel had to fan out to the workers itself,
// that would cause greater kernel contention than
// sending the single seed value.
type SeedChannels struct {
	ForwardJoins chan SeedForwardJoin
}

func NewSeedChannels(chanSz int) SeedChannels {
	return SeedChannels{
		ForwardJoins: make(chan SeedForwardJoin, chanSz),
	}
}

type WorkChannels struct {
	ForwardJoins chan WorkForwardJoin

	OutboundShuffles       chan WorkOutboundShuffle
	OutboundShuffleReplies chan WorkOutboundShuffleReply
}

func NewWorkChannels(chanSz int) WorkChannels {
	return WorkChannels{
		ForwardJoins:           make(chan WorkForwardJoin, chanSz),
		OutboundShuffles:       make(chan WorkOutboundShuffle, chanSz),
		OutboundShuffleReplies: make(chan WorkOutboundShuffleReply, chanSz),
	}
}

// fanoutSeedForwardJoin allows the kernel to provide
// one message and a collection of streams.
// Then one fanout worker encodes the message into a byte slice,
// and fans it out to all fanout workers through the work channels.
type SeedForwardJoin struct {
	Msg dprotoi.ForwardJoinMessage

	Streams []quic.Stream
}

// WorkForwardJoin is the translation of a [SeedForwardJoin] into fanout work.
type WorkForwardJoin struct {
	Raw []byte

	Stream quic.Stream
}

// WorkOutboundShuffle is a shuffle message destined for a particular peer.
// Because this message has only one destination,
// we skip the seed stage.
//
// The worker is responsible for creating the ephemeral stream
// for the shuffle.
type WorkOutboundShuffle struct {
	Msg dprotoi.ShuffleMessage

	Conn quic.Connection

	// We should already have the chain anyway,
	// so include it here so the worker
	// so that the worker doesn't have to recalculate it.
	Chain dcert.Chain
}

// WorkOutboundShuffleReply is the shuffle reply sent in response to a peer's
// initiated shuffle to us.
//
// After sending the reply, the worker is responsible
// for closing the ephemeral stream.
type WorkOutboundShuffleReply struct {
	Msg dprotoi.ShuffleReplyMessage

	Stream quic.Stream
}

type WorkerOutputChannels struct {
	ShuffleRepliesFromPeers chan<- dmsg.ShuffleReplyFromPeer
}
