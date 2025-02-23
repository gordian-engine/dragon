package dproto

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/gordian-engine/dragon/internal/dcrypto"
)

// AddressAttestation is a signature of an advertised address and timestamp.
//
// The signature is proof that a particular certificate
// was advertising a particular address at a particular time.
//
// This is used in:
//   - [JoinMessage] so that the contact node can include the attestation in the [ForwardJoinMessage]
//   - [NeighborMessage] so that the target node can use that attestation in a [ShuffleMessage].
//
// And we may eventually have a way for already peered nodes
// to transfer an updated attestation,
// which would be useful for shuffles too.
type AddressAttestation struct {
	// The advertised address, so other nodes can dial it.
	Addr string

	// The time that the attestation was signed.
	// This value is encoded across the wire as a 64-bit unix time,
	// i.e. seconds since Jan 1 1970;
	// so upon decoding, the value will be truncated to a whole second value.
	Timestamp time.Time

	// The cryptographic signature of the address and timestamp.
	// See the AppendSignContent method for details.
	Signature []byte
}

func (a AddressAttestation) AppendSignContent(dst []byte) []byte {
	sz := len(a.Addr) + 1 + 8
	if cap(dst) < sz {
		dst = make([]byte, 0, sz)
	}

	ts := a.Timestamp.Unix()

	dst = append(dst, a.Addr...)
	dst = append(dst, '\n')

	// There is no AppendInt64 method in the binary package.
	// If you look at the general implementation of Append,
	// you will see that they handle int64 this way:
	dst = binary.BigEndian.AppendUint64(dst, uint64(ts))

	return dst
}

func (a AddressAttestation) VerifySignature(signingCert *x509.Certificate) error {
	if err := dcrypto.VerifySignatureWithTLSCert(
		a.AppendSignContent(nil),
		signingCert,
		a.Signature,
	); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// EncodedSize returns the length of the data to be encoded.
// This can be useful for pre-sizing buffers.
func (a AddressAttestation) EncodedSize() int {
	return 1 + // 1-byte length of address
		len(a.Addr) +
		8 + // 64-bit timestamp
		2 + // 16-bit signature length
		len(a.Signature)
}

func (a AddressAttestation) Encode(w io.Writer) error {
	if len(a.Addr) > 255 {
		panic(fmt.Errorf(
			"ILLEGAL: advertised address must be <= 255 bytes, but %q is %d bytes",
			a.Addr, len(a.Addr),
		))
	}
	if len(a.Signature) > (1<<16)-1 {
		panic(fmt.Errorf(
			"ILLEGAL: signature length must fit in uint16, but signature is %d bytes",
			len(a.Signature),
		))
	}

	out := make([]byte, 0,
		1+ // 1-byte length of address
			len(a.Addr)+
			8+ // 64-bit timestamp
			2+ // 16-bit signature length
			len(a.Signature),
	)

	out = append(out, byte(len(a.Addr)))
	out = append(out, a.Addr...)
	out = binary.BigEndian.AppendUint64(out, uint64(a.Timestamp.Unix()))
	out = binary.BigEndian.AppendUint16(out, uint16(len(a.Signature)))
	out = append(out, a.Signature...)

	// Shouldn't need to wrap this error,
	// as the caller (a message Encode method)
	// should be expected to wrap this.
	_, err := w.Write(out)
	return err
}

func (a *AddressAttestation) Decode(r io.Reader) error {
	var addrLenBuf [1]byte
	if _, err := io.ReadFull(r, addrLenBuf[:]); err != nil {
		return fmt.Errorf("failed to read address length: %w", err)
	}

	addrLen := addrLenBuf[0]

	// addrLen is almost certainly more than 8, but make sure anyway.
	buf := make([]byte, max(addrLen, 8))

	if _, err := io.ReadFull(r, buf[:addrLen]); err != nil {
		return fmt.Errorf("failed to read addres: %w", err)
	}
	a.Addr = string(buf[:addrLen])

	if _, err := io.ReadFull(r, buf[:8]); err != nil {
		return fmt.Errorf("failed to read timestamp: %w", err)
	}
	a.Timestamp = time.Unix(
		int64(binary.BigEndian.Uint64(buf[:8])), 0,
	)

	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return fmt.Errorf("failed to read signature length: %w", err)
	}
	sigLen := binary.BigEndian.Uint16(buf[:2])

	// Just a guess on a generous upper limit of signature size.
	const maxSigLen = 2048
	if sigLen > maxSigLen {
		return fmt.Errorf("invalid format: signature length %d too large", sigLen)
	}

	// Reuse the existing slice for signature, if possible.
	if cap(a.Signature) < int(sigLen) {
		a.Signature = make([]byte, sigLen)
	}
	if _, err := io.ReadFull(r, a.Signature[:sigLen]); err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	// Leave the capacity alone,
	// but make sure the signature slice has the correct length.
	a.Signature = a.Signature[:sigLen]

	return nil
}
