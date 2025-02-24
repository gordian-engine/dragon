package dproto

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dcert"
)

// ForwardJoin message is conditionally sent to active peers
// when a Node receives a [JoinMessage].
type ForwardJoinMessage struct {
	// The initial address attestation sent by the joining node.
	AA daddr.AddressAttestation

	// The certificate chain of the joining node.
	Chain dcert.Chain

	// How many more hops the join may go.
	TTL uint8
}

func (m ForwardJoinMessage) Verify() error {
	// TODO
	return nil
}

func (m ForwardJoinMessage) Encode(w io.Writer) error {
	if err := m.Chain.Validate(); err != nil {
		panic(fmt.Errorf("ILLEGAL: attempted to encode invalid chain: %w", err))
	}

	// Put as much as possible in the first send buffer.
	sz := 1 + // Forward join message type.
		m.AA.EncodedSize() +
		m.Chain.EncodedSize() +
		1 // uint8 TTL.

	buf := bytes.NewBuffer(make([]byte, 0, sz))
	_ = buf.WriteByte(byte(ForwardJoinMessageType))

	// bytes.Buffer is documented to always return nil for write operations.
	// And currently, (daddr.AddressAttestation).Encode can only return an error
	// from the underlying writer, so this should never fail.
	if err := m.AA.Encode(buf); err != nil {
		panic(errors.New(
			"BUG: encoding an address attestation should never fail",
		))
	}

	if err := m.Chain.Encode(buf); err != nil {
		return fmt.Errorf("failed to encode chain: %w", err)
	}

	// And finally, the TTL byte.
	_ = buf.WriteByte(m.TTL)

	_, err := buf.WriteTo(w)
	if err != nil {
		return fmt.Errorf("failed to write encoded forward join: %w", err)
	}

	return nil
}

func (m *ForwardJoinMessage) Decode(r io.Reader) error {
	// We have to assume the header byte has already been consumed.
	// So, we can decode the address attestation first.
	if err := m.AA.Decode(r); err != nil {
		return fmt.Errorf("failed to decode address attestation: %w", err)
	}

	// TODO: replace most of this with Chain.Decode.
	if err := m.Chain.Decode(r); err != nil {
		return fmt.Errorf("failed to decode chain: %w", err)
	}

	// Finally, read one more byte for the TTL.
	var szBuf [1]byte
	if _, err := io.ReadFull(r, szBuf[:]); err != nil {
		return fmt.Errorf("failed to read TTL byte: %w", err)
	}

	m.TTL = szBuf[0]

	return nil
}
