package dproto

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// JoinMessage is the message a client sends to a server
// when it wants to enter the p2p network.
type JoinMessage struct {
	// Addr here is the address to advertise for other nodes to dial
	// if they want to make a neighbor request.
	Addr string

	// Timestamp is the RFC3339 timestamp when this join message was created and signed.
	Timestamp string

	// The cryptographic signature across the timestamp and address.
	// The signer must be the same key as in the TLS certificate used in this and future connections.
	Signature []byte
}

// SetTimestamp sets m's Timestamp field in the expected format.
func (m *JoinMessage) SetTimestamp(t time.Time) {
	m.Timestamp = t.UTC().Format(time.RFC3339)
}

// AppendSignContent appends the signing content to dst,
// allowing the caller to control allocations.
//
// Constructing and verifying the signature must be done manually.
func (m JoinMessage) AppendSignContent(dst []byte) []byte {
	if dst == nil {
		dst = make([]byte, 0, len(m.Timestamp)+1+len(m.Addr))
	}
	// Timestamp goes first because it's a fixed length value.
	dst = append(dst, m.Timestamp...)
	dst = append(dst, '\n')
	dst = append(dst, m.Addr...)
	return dst
}

// OpenStreamAndJoinBytes returns the byte slice to send
// on a new connection, including both the stream identifier
// and the content for this Join message.
// This allows us to make only a single allocation,
// and to more likely cover all that data in a single sent packet.
func (m JoinMessage) OpenStreamAndJoinBytes() []byte {
	if len(m.Addr) > 255 {
		panic(fmt.Errorf(
			"ILLEGAL: advertised address must be <= 255 bytes, but %q is %d bytes",
			m.Addr, len(m.Addr),
		))
	}

	// Out buffer format:
	// 1 byte protocol version, 1 byte stream identifier,
	// 1 byte join message ID,
	// 1 byte address length,
	// 2 bytes big endian signature length (can be >256 bytes),
	// variable length address,
	// fixed length RFC3339 timestamp,
	// variable length signature.
	//
	// TODO: we need to include the certificate here somehow too, I think.
	// But maybe the Join message recipient could just extract it?
	sz := 1 + 1 +
		1 +
		1 +
		2 +
		len(m.Addr) +
		joinMessageTimestampLen +
		len(m.Signature)

	out := make([]byte, 0, sz)
	out = append(out,
		CurrentProtocolVersion, byte(AdmissionStreamType),
		byte(JoinMessageType),
		byte(len(m.Addr)),
	)
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.Signature)))
	out = append(out, m.Addr...)
	out = append(out, m.Timestamp...)
	out = append(out, m.Signature...)

	return out
}

// joinMessageTimestampLen is the length of the formatted timestamp.
// We have to use the length of a formatted literal,
// not the length of the time.RFC3339 constant,
// because we force UTC time which fixes the time zone to empty.
const joinMessageTimestampLen = len("2006-01-02T15:04:05Z")

// Decode reads from r and populates all fields in m.
// No verification is performed.
// It is expected that the reader has already consumed the join message type byte
// (because it had to know whether to decode a join message or a neighbor message).
func (m *JoinMessage) Decode(r io.Reader) error {
	// We expect 3 bytes of sizes.
	var buf [3]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return fmt.Errorf("failed to read sizes for serialized join message: %w", err)
	}

	// Determine both sizes.
	addrSize := int(buf[0])

	// Nobody in their right mind would use a single character hostname
	// and a single-digit port for this service.
	// Pick 4 to require at least a double digit port.
	const minAddrSize = 4
	if addrSize < minAddrSize {
		return fmt.Errorf(
			"invalid format: address size must be at least %d (got %d)",
			minAddrSize, addrSize,
		)
	}

	sigSize := int(binary.BigEndian.Uint16(buf[1:]))

	// I don't know what this actually should be,
	// but put a reasonably estimated cap on signature size,
	// so we can prevent reading 65k-sized signatures from a malicious remote.
	const maxAllowedSigSize = 2048
	if sigSize > maxAllowedSigSize {
		return fmt.Errorf("invalid format: signature size %d too large", sigSize)
	}

	// Only allocate one byte buffer since the first two values are going to be copied to strings.
	valBuf := make([]byte, 0, max(addrSize, joinMessageTimestampLen, sigSize))

	if _, err := io.ReadFull(r, valBuf[:addrSize]); err != nil {
		return fmt.Errorf("failed to read join message address: %w", err)
	}
	m.Addr = string(valBuf[:addrSize])

	if _, err := io.ReadFull(r, valBuf[:joinMessageTimestampLen]); err != nil {
		return fmt.Errorf("failed to read join message timestamp: %w", err)
	}
	m.Timestamp = string(valBuf[:joinMessageTimestampLen])

	// We could potentially parse and validate the timestamp now,
	// but we will leave that to the caller.

	if _, err := io.ReadFull(r, valBuf[:sigSize]); err != nil {
		return fmt.Errorf("failed to read join message signature: %w", err)
	}
	// Clip capacity from the slice, to possibly simplify GC.
	m.Signature = valBuf[:sigSize:sigSize]

	return nil
}
