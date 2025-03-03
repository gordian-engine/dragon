package dprotoi

import "time"

// StreamType is a single byte header sent when initiating a stream to a peer.
type StreamType byte

const (
	// Keep zero reserved.
	// Not using iota here, to avoid possibility of values changing across the wire.

	// Bidirectional stream, initiated by the client upon opening the connection.
	//
	// Client may send a Join message.
	// If server accepts the Join, server sends a Neighbor message on the same stream.
	// Client may respond to Neighbor message with an explicit NeighborReply,
	// accepting or rejecting the Neighbor request;
	// or client may silently ignore the Neighbor request.
	//
	// Between established neighbors, either side may send a ForwardJoin.
	AdmissionStreamType = 1

	// Bidirectional stream, initiated by the client upon opening the connection.
	// Either peer may send a Disconnect message to initiate a clean shutdown.
	//
	// This is a dedicated stream to increase the likelihood that a standalone,
	// small Disconnect message may be handled before other, larger messages.
	DisconnectStreamType = 2

	// Bidirectional stream, initiated by the client following a NeighborReply.
	//
	// Either peer may send a Shuffle message,
	// and then the other side should respond with a ShuffleReply.
	//
	// This is a dedicated stream because the messages can potentially be larger,
	// depending on the number of peers transmitted;
	// and the shuffle message stream should preferably not interfere with
	// the other protocol streams.
	ShuffleStreamType = 3
)

// OpenStreamTimeout is the write timeout when sending the stream type header.
// This is a constant for now, but it should be configurable.
const OpenStreamTimeout = time.Second

// ReceiveInitialStreamsTimeout is the read timeout for accepting the extra streams
// following reception of a positive neighbor reply.
// This is a constant for now, but it should be configurable.
const ReceiveInitialStreamsTimeout = time.Second

// ReceiveInitialStreamsTimeout is the write timeout for accepting the extra streams
// following reception of a positive neighbor reply.
// This is a constant for now, but it should be configurable.
const InitializeStreamsTimeout = time.Second
