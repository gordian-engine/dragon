package dragon

import "github.com/quic-go/quic-go"

// streams is the collecion of streams within a connection.
type streams struct {
	// Connection stream:
	// We may have sent a Join message.
	// We may send or receive ForwardJoin messages.
	// We may send or receive a Neighbor or NeighborReply message.
	Admission quic.Stream
}
