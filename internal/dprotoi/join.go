package dprotoi

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/gordian-engine/dragon/daddr"
)

// JoinMessage is the message a client sends to a server
// when it wants to enter the p2p network.
type JoinMessage struct {
	// The join message currently only contains an address attestation.
	AA daddr.AddressAttestation
}

// OpenStreamAndJoinBytes returns the byte slice to send
// on a new connection, including both the stream identifier
// and the content for this Join message.
// This allows us to make only a single allocation,
// and to more likely cover all that data in a single sent packet.
func (m JoinMessage) OpenStreamAndJoinBytes() []byte {
	// Out buffer format:
	// 1 byte protocol version, 1 byte stream identifier,
	// 1 byte join message ID,
	// then the address attestation.
	sz := 3 + m.AA.EncodedSize()

	buf := bytes.NewBuffer(make([]byte, 0, sz))
	_ = buf.WriteByte(CurrentProtocolVersion)
	_ = buf.WriteByte(byte(AdmissionStreamType))
	_ = buf.WriteByte(byte(JoinMessageType))

	// bytes.Buffer is documented to always return nil for write operations.
	// And currently, (daddr.AddressAttestation).Encode can only return an error
	// from the underlying writer, so this should never fail.
	if err := m.AA.Encode(buf); err != nil {
		panic(errors.New(
			"BUG: encoding an address attestation should never fail",
		))
	}

	return buf.Bytes()
}

// Decode reads from r and populates all fields in m.
// No verification is performed.
// It is expected that the reader has already consumed the join message type byte
// (because it had to know whether to decode a join message or a neighbor message).
func (m *JoinMessage) Decode(r io.Reader) error {
	if err := m.AA.Decode(r); err != nil {
		return fmt.Errorf("failed to decode AddressAttestation: %w", err)
	}

	return nil
}
