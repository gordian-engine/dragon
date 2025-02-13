package dproto

type NeighborReplyMessage struct {
	Accepted bool
}

func (m NeighborReplyMessage) Bytes() []byte {
	out := [2]byte{
		byte(NeighborReplyMessageType),
		0,
	}
	if m.Accepted {
		out[1] = 1
	}

	return out[:]
}
