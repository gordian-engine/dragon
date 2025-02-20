package dfanout

import (
	"github.com/gordian-engine/dragon/internal/dproto"
	"github.com/quic-go/quic-go"
)

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
}

func NewWorkChannels(chanSz int) WorkChannels {
	return WorkChannels{
		ForwardJoins: make(chan WorkForwardJoin, chanSz),
	}
}

// fanoutSeedForwardJoin allows the kernel to provide
// one message and a collection of streams.
// Then one fanout worker encodes the message into a byte slice,
// and fans it out to all fanout workers through the work channels.
type SeedForwardJoin struct {
	Msg dproto.ForwardJoinMessage

	Streams []quic.Stream
}

// WorkForwardJoin is the translation of a [SeedForwardJoin] into fanout work.
type WorkForwardJoin struct {
	Raw []byte

	Stream quic.Stream
}
