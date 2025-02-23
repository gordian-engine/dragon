package dproto

import (
	"fmt"
	"io"
)

type NeighborMessage struct {
	AA AddressAttestation
}

// Decode reads from r and populates all fields in m.
// No verification is performed.
// It is expected that the reader has already consumed the neighbor message type byte
// (because it had to know whether to decode a join message or a neighbor message).
func (m *NeighborMessage) Decode(r io.Reader) error {
	if err := m.AA.Decode(r); err != nil {
		return fmt.Errorf("failed to decode AddressAttestation: %w", err)
	}

	return nil
}

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
