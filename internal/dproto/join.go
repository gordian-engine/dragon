package dproto

import "fmt"

// JoinMessage is the message a client sends to a server
// when it wants to enter the p2p network.
type JoinMessage struct {
	// Addr here is the address to advertise for other nodes to dial
	// if they want to make a neighbor request.
	Addr string
}

// OpenStreamAndJoinBytes returns the byte slice to send
// on a new connection, including both the stream identifier
// and the content for this Join message.
// This allows us to make only a single allocation,
// and to more likely cover all that data in a single sent packet.
func (j JoinMessage) OpenStreamAndJoinBytes() []byte {
	if len(j.Addr) > 255 {
		panic(fmt.Errorf(
			"ILLEGAL: advertised address must be <= 255 bytes, but %q is %d bytes",
			j.Addr, len(j.Addr),
		))
	}

	// Protocol and Stream ID,
	// plus Type-Length, plus our address.
	sz := 2 + 2 + len(j.Addr)
	out := make([]byte, 4, sz)
	out[0] = CurrentProtocolVersion
	out[1] = byte(AdmissionStreamType)
	out[2] = byte(JoinMessageType)
	out[3] = byte(len(j.Addr))

	out = append(out, j.Addr...)
	return out
}
