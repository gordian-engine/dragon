package dproto

import "time"

// MessageType is a single byte header indicating the type of message.
type MessageType byte

const (
	// Keep zero reserved.
	// Not using iota here, to avoid possibility of values changing across the wire.

	// A new node wants to join the network.
	JoinMessageType MessageType = 1

	// Announce to peers that there is a new node who wants to join the network.
	ForwardJoinMessageType MessageType = 2
)

// AwaitNeighborTimeout is the read timeout for waiting for a neighbor reply message.
// This is a constant for now, but it should be configurable.
const AwaitNeighborTimeout = time.Second
