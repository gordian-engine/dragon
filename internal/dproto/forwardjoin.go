package dproto

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
)

// ForwardJoin message is conditionally sent to active peers
// when a Node receives a [JoinMessage].
type ForwardJoinMessage struct {
	// The initial message sent by the joining node.
	JoinMessage JoinMessage

	// The certificate chain of the joining node.
	JoiningCertChain []*x509.Certificate

	TTL uint8
}

func (m ForwardJoinMessage) Verify() error {
	// TODO
	return nil
}

func (m ForwardJoinMessage) Encode(w io.Writer) (int, error) {
	if len(m.JoinMessage.Addr) > 255 {
		panic(fmt.Errorf(
			"ILLEGAL: tried to encode join address of %d bytes but limit is 255 (%q)",
			len(m.JoinMessage.Addr), m.JoinMessage.Addr,
		))
	}
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

	buf := make([]byte, 2, 4)
	buf[0] = byte(ForwardJoinMessageType)
	buf[1] = byte(len(m.JoinMessage.Addr))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(m.JoinMessage.Signature)))

	// Sizes for join message.
	nn, err := w.Write(buf)
	if err != nil {
		return nn, fmt.Errorf("failed to write message header: %w", err)
	}
	n := nn

	// Join message content.
	nn, err = io.WriteString(w, m.JoinMessage.Addr)
	n += nn
	if err != nil {
		return n, fmt.Errorf("failed to write join message address: %w", err)
	}

	nn, err = io.WriteString(w, m.JoinMessage.Timestamp)
	n += nn
	if err != nil {
		return n, fmt.Errorf("failed to write join message timestamp: %w", err)
	}

	nn, err = w.Write(m.JoinMessage.Signature)
	n += nn
	if err != nil {
		return n, fmt.Errorf("failed to write join message signature: %w", err)
	}

	// Next, the number of certificates in the chain, plus the TTL.
	buf = make([]byte, 1, 1+(2*len(m.JoiningCertChain))+1)
	buf[0] = byte(len(m.JoiningCertChain))

	for _, c := range m.JoiningCertChain {
		const maxUint16 = (1 << 16) - 1
		if len(c.Raw) > maxUint16 {
			panic(fmt.Errorf(
				"ILLEGAL: cannot use certificate with length greater than %d",
				maxUint16,
			))
		}
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.Raw)))
	}

	buf = append(buf, m.TTL)

	nn, err = w.Write(buf)
	n += nn
	if err != nil {
		return n, fmt.Errorf("failed to write certificate count and sizes: %w", err)
	}

	for i, c := range m.JoiningCertChain {
		nn, err = w.Write(c.Raw)
		n += nn
		if err != nil {
			return n, fmt.Errorf("failed to write certificate at index %d: %w", i, err)
		}
	}

	return n, nil
}

func (m *ForwardJoinMessage) Decode(r io.Reader) error {
	// We have to assume the header byte has already been consumed.
	// So, first we read three bytes for the join message lengths.
	var szBuf [3]byte
	if _, err := io.ReadFull(r, szBuf[:]); err != nil {
		return fmt.Errorf("failed to read forward join message first sizes: %w", err)
	}

	addrSz := szBuf[0]
	sigSz := binary.BigEndian.Uint16(szBuf[1:])

	jmBuf := make([]byte, max(int(addrSz), joinMessageTimestampLen, int(sigSz)))
	if _, err := io.ReadFull(r, jmBuf[:addrSz]); err != nil {
		return fmt.Errorf("failed to read forward join address: %w", err)
	}
	m.JoinMessage.Addr = string(jmBuf[:addrSz])

	if _, err := io.ReadFull(r, jmBuf[:joinMessageTimestampLen]); err != nil {
		return fmt.Errorf("failed to read forward join timestamp: %w", err)
	}
	m.JoinMessage.Timestamp = string(jmBuf[:joinMessageTimestampLen])

	if _, err := io.ReadFull(r, jmBuf[:sigSz]); err != nil {
		return fmt.Errorf("failed to read forward join signature: %w", err)
	}
	// Take ownership of jmBuf for the signature.
	m.JoinMessage.Signature = jmBuf[:sigSz:sigSz]

	// Now the count of certificates.
	if _, err := io.ReadFull(r, szBuf[:1]); err != nil {
		return fmt.Errorf("failed to read certificate count: %w", err)
	}

	// Now we know how many certificate sizes to read. Plus the TTL.
	cSizes := make([]byte, (2*szBuf[0])+1)
	if _, err := io.ReadFull(r, cSizes); err != nil {
		return fmt.Errorf("failed to read certificate sizes: %w", err)
	}

	m.TTL = cSizes[len(cSizes)-1]

	if cap(m.JoiningCertChain) >= int(szBuf[0]) {
		m.JoiningCertChain = m.JoiningCertChain[:szBuf[0]]
	} else {
		m.JoiningCertChain = make([]*x509.Certificate, szBuf[0])
	}

	for i := range m.JoiningCertChain {
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

	return nil
}
