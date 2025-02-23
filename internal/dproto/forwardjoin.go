package dproto

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ForwardJoin message is conditionally sent to active peers
// when a Node receives a [JoinMessage].
type ForwardJoinMessage struct {
	// The initial address attestation sent by the joining node.
	AA AddressAttestation

	// The certificate chain of the joining node.
	JoiningCertChain []*x509.Certificate

	// How many more hops the join may go.
	TTL uint8
}

func (m ForwardJoinMessage) Verify() error {
	// TODO
	return nil
}

func (m ForwardJoinMessage) Encode(w io.Writer) error {
	if len(m.JoiningCertChain) > 255 {
		panic(fmt.Errorf(
			"ILLEGAL: joining cert chain too long (%d)",
			len(m.JoiningCertChain),
		))
	}
	if len(m.JoiningCertChain) < 2 {
		panic(fmt.Errorf(
			"ILLEGAL: joining cert chain must be at least 2, got %d",
			len(m.JoiningCertChain),
		))
	}

	// Put as much as possible in the first send buffer.
	sz := 1 + // Forward join message type.
		m.AA.EncodedSize() +
		1 + // uint8 number of certificates in the chain.
		(2 * len(m.JoiningCertChain)) + // uint16 for each cert size.
		1 // uint8 TTL.

	// TODO: we could save a bit of space by not encoding the raw CA certificate.
	// We expect the remote to already have it.
	// So we could send the unique identifier of its RawSubjectPublicKeyInfo.
	for _, c := range m.JoiningCertChain {
		sz += len(c.Raw)
	}

	buf := bytes.NewBuffer(make([]byte, 0, sz))
	_ = buf.WriteByte(byte(ForwardJoinMessageType))

	// bytes.Buffer is documented to always return nil for write operations.
	// And currently, (AddressAttestation).Encode can only return an error
	// from the underlying writer, so this should never fail.
	if err := m.AA.Encode(buf); err != nil {
		panic(errors.New(
			"BUG: encoding an address attestation should never fail",
		))
	}

	// Number of certificates in the chain.
	_ = buf.WriteByte(byte(len(m.JoiningCertChain)))

	// Each raw certificate size.
	for _, c := range m.JoiningCertChain {
		const maxUint16 = (1 << 16) - 1
		if len(c.Raw) > maxUint16 {
			panic(fmt.Errorf(
				"ILLEGAL: cannot use certificate with length greater than %d",
				maxUint16,
			))
		}
		if err := binary.Write(buf, binary.BigEndian, uint16(len(c.Raw))); err != nil {
			panic(fmt.Errorf(
				"IMPOSSIBLE: failed to encode big endian uint16: %w", err,
			))
		}
	}

	// Now loop again and write the raw certificate data.
	// If we really wanted to, we could roll this in the above loop,
	// but these chains should be short enough
	// that it wouldn't be a noticeable difference.
	for _, c := range m.JoiningCertChain {
		_, _ = buf.Write(c.Raw)
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

	// Next in the encode sequence is the number of certificates.
	var szBuf [1]byte
	if _, err := io.ReadFull(r, szBuf[:]); err != nil {
		return fmt.Errorf("failed to read certificate count: %w", err)
	}

	// Read in the certificate sizes.
	cSizes := make([]byte, 2*szBuf[0])
	if _, err := io.ReadFull(r, cSizes); err != nil {
		return fmt.Errorf("failed to read certificate sizes: %w", err)
	}

	// Right-size the joining cert chain.
	if cap(m.JoiningCertChain) >= int(szBuf[0]) {
		m.JoiningCertChain = m.JoiningCertChain[:szBuf[0]]
	} else {
		m.JoiningCertChain = make([]*x509.Certificate, szBuf[0])
	}

	for i := range m.JoiningCertChain {
		// We have to allocate a byte slice,
		// and the call to x509.ParseCertificate will take ownership of it.
		raw := make([]byte, binary.BigEndian.Uint16(cSizes))
		cSizes = cSizes[2:]

		_, err := io.ReadFull(r, raw)
		if err != nil {
			return fmt.Errorf("failed to read raw certificate at index %d: %w", i, err)
		}

		m.JoiningCertChain[i], err = x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("failed to parse certificate at index %d: %w", i, err)
		}
	}

	// Finally, read one more byte for the TTL.
	// We already had a 1-byte slice we can reuse for that.
	if _, err := io.ReadFull(r, szBuf[:]); err != nil {
		return fmt.Errorf("failed to read TTL byte: %w", err)
	}

	m.TTL = szBuf[0]

	return nil
}
