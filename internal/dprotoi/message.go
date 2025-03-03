package dprotoi

import "time"

// MessageType is a single byte header indicating the type of message.
type MessageType uint8

const (
	// Keep zero reserved.
	// Not using iota here, to avoid possibility of values changing across the wire.

	// A new node wants to join the network.
	JoinMessageType MessageType = 1

	// Announce to peers that there is a new node who wants to join the network.
	ForwardJoinMessageType MessageType = 2

	// Request to become peers with the remote end.
	// This is only half of the peering process;
	// the contact node must respond with a positive neighbor reply message.
	NeighborMessageType MessageType = 3

	// Response to neighbor request.
	NeighborReplyMessageType MessageType = 4

	// Self-initiated shuffle to a randomly chosen active peer.
	ShuffleMessageType MessageType = 5

	// Reply to shuffle message.
	ShuffleReplyMessageType MessageType = 6
)

const (
	// NeighborRequestTimeout is the write timeout for sending a neighbor request.
	// This is a constant for now, but it should be configurable.
	NeighborRequestTimeout = time.Second

	// AwaitNeighborTimeout is the read timeout for waiting for a neighbor reply message.
	// This is a constant for now, but it should be configurable.
	AwaitNeighborTimeout = time.Second
)
