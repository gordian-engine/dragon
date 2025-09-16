package wspacket

// OutboundPacket is an opaque view of a single outgoing packet.
//
// OutboundPacket values are accessed through [OutboundRemoteState.UnsentPackets].
type OutboundPacket interface {
	// Bytes is the raw byte slice that needs to be sent
	// to the peer over a QUIC stream.
	//
	// To minimize allocations,
	// independent packets should return the same underlying slice.
	// Callers will not modify the slice.
	Bytes() []byte

	// After sending a packet to a peer,
	// Wingspan internals call MarkSent
	// in order to update the [OutboundRemoteState],
	// which will influence future calls to [OutboundRemoteState.UnsentPackets].
	MarkSent()
}
