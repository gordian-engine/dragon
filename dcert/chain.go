package dcert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"
)

// A [Chain] may have up to 7 intermediate entries,
// in addition to its leaf and root certificates.
//
// Seven was a mostly arbitrary choice.
// It seems generous enough for any practical chain,
// and seven can be represented in only 3 bits,
// if we need to pack that length with anything else.
const MaxIntermediateLen = 7

// Chain represents a certificate chain,
// with slightly stronger typing contextual to dragon
// compared to a simple slice of *x509.Certificate.
//
// A Chain in dragon is required to have a non-nil leaf and root,
// but intermediate may have up to seven entries.
//
// Since a Chain only contains three reference values,
// a Chain is typically passed by value, not by reference.
type Chain struct {
	Leaf *x509.Certificate

	Intermediate []*x509.Certificate

	Root *x509.Certificate
}

// NewChainFromCerts returns a Chain from the given list of certificates.
func NewChainFromCerts(certs []*x509.Certificate) (Chain, error) {
	if len(certs) < 2 {
		return Chain{}, fmt.Errorf(
			"chain must have at least two entries (got %d)", len(certs),
		)
	}
	if len(certs) > 2+MaxIntermediateLen {
		return Chain{}, fmt.Errorf(
			"chain is limited to seven intermediate certificates (full chain had %d)",
			len(certs)-2,
		)
	}

	chain := Chain{
		Leaf: certs[0],
		Root: certs[len(certs)-1],
	}

	if len(certs) > 2 {
		// We want chain.Intermediate to be nil, not an empty slice,
		// when there are no intermediates.
		// If it is an empty slice, some tests involving decoding can fail.
		// Using slices.Clip has a chance of helping GC.
		chain.Intermediate = slices.Clip(certs[1 : len(certs)-1])
	}

	return chain, nil
}

func NewChainFromTLSConnectionState(s tls.ConnectionState) (Chain, error) {
	if len(s.VerifiedChains) == 0 {
		return Chain{}, errors.New("connection state had no verified chains")
	}

	return NewChainFromCerts(s.VerifiedChains[0])
}

func (c Chain) Validate() error {
	var err error
	if c.Leaf == nil {
		err = errors.Join(err, errors.New("Chain.Leaf must not be nil"))
	}

	if len(c.Intermediate) > MaxIntermediateLen {
		err = errors.Join(err, fmt.Errorf(
			"%d intermediate entries exceeds limit of %d",
			len(c.Intermediate), MaxIntermediateLen,
		))
	}

	if c.Root == nil {
		err = errors.Join(err, errors.New("Chain.Root must not be nil"))
	}

	return err
}

// Len returns the total number of certificates in the chain.
// Due to the limit of 7 intermediate certificates,
// the returned value for a valid chain will be in range [2,9].
func (c Chain) Len() int {
	return 2 + len(c.Intermediate)
}

// All returns an iterator over every certificate in c,
// starting with the leaf and ending with the root.
func (c Chain) All() iter.Seq[*x509.Certificate] {
	return func(yield func(*x509.Certificate) bool) {
		if !yield(c.Leaf) {
			return
		}

		for _, i := range c.Intermediate {
			if !yield(i) {
				return
			}
		}

		if !yield(c.Root) {
			return
		}
	}
}

// Mutable returns an iterator over mutable certificates.
// This is particularly useful when deserializing a Chain.
// This iterator abstracts away the fact that
// only the Chain's intermediate field is a slice.
func (c *Chain) Mutable() iter.Seq[MutableCert] {
	return func(yield func(MutableCert) bool) {
		mc := MutableCert{target: &c.Leaf}
		if !yield(mc) {
			return
		}

		for _, im := range c.Intermediate {
			mc.target = &im
			if !yield(mc) {
				return
			}
		}

		mc.target = &c.Root
		if !yield(mc) {
			return
		}
	}
}

// MutableCert is a mutable certificate within the chain.
type MutableCert struct {
	target **x509.Certificate
}

// Set sets the mutable certificate to the given certificate.
func (mc MutableCert) Set(cert *x509.Certificate) {
	*mc.target = cert
}

func (c Chain) EncodedSize() int {
	sz := 1 + (2 * c.Len()) // Number of intermediate certs, plus uint16 for each cert's size.
	for cert := range c.All() {
		sz += len(cert.Raw)
	}
	return sz
}

func (c Chain) Encode(w io.Writer) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("refusing to encode invalid Chain: %w", err)
	}

	sz := c.EncodedSize()

	buf := bytes.NewBuffer(make([]byte, 0, sz))
	_ = buf.WriteByte(byte(c.Len()))

	for cert := range c.All() {
		const maxUint16 = (1 << 16) - 1
		if len(cert.Raw) > maxUint16 {
			panic(fmt.Errorf(
				"ILLEGAL: cannot encode certificate with length greater than %d",
				maxUint16,
			))
		}
		if err := binary.Write(buf, binary.BigEndian, uint16(len(cert.Raw))); err != nil {
			panic(fmt.Errorf(
				"IMPOSSIBLE: failed to encode big endian uint16: %w", err,
			))
		}
	}

	// TODO: we could save a bit of space by not encoding the raw CA certificate.
	// We expect the remote to already have it.
	// So we could send the unique identifier of its RawSubjectPublicKeyInfo.

	for cert := range c.All() {
		_, _ = buf.Write(cert.Raw)
	}

	_, err := buf.WriteTo(w)
	if err != nil {
		return fmt.Errorf("failed to write encoded chain: %w", err)
	}

	return nil
}

func (c *Chain) Decode(r io.Reader) error {
	var szBuf [1]byte
	if _, err := io.ReadFull(r, szBuf[:]); err != nil {
		return fmt.Errorf("failed to read certificate count: %w", err)
	}

	if szBuf[0] < 2 {
		return fmt.Errorf("certificate count %d too small (must be at least 2)", szBuf[0])
	}
	if szBuf[0] > 2+MaxIntermediateLen {
		return fmt.Errorf(
			"certificate count %d too high (must be no greater than %d",
			szBuf[0], 2+MaxIntermediateLen,
		)
	}

	// Read in the certificate sizes.
	cSizes := make([]byte, 2*szBuf[0])
	if _, err := io.ReadFull(r, cSizes); err != nil {
		return fmt.Errorf("failed to read certificate sizes: %w", err)
	}

	// Right-size the joining cert chain.
	szBuf[0] -= 2
	if cap(c.Intermediate) >= int(szBuf[0]) {
		c.Intermediate = c.Intermediate[:szBuf[0]]
	} else {
		c.Intermediate = make([]*x509.Certificate, szBuf[0])
	}

	i := 0
	for mc := range c.Mutable() {
		// We have to allocate a byte slice,
		// and the call to x509.ParseCertificate will take ownership of it.
		raw := make([]byte, binary.BigEndian.Uint16(cSizes))
		cSizes = cSizes[2:]

		if _, err := io.ReadFull(r, raw); err != nil {
			return fmt.Errorf("failed to read raw certificate at index %d: %w", i, err)
		}

		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("failed to parse certificate at index %d: %w", i, err)
		}
		mc.Set(cert)
		i++
	}

	if err := c.Validate(); err != nil {
		return fmt.Errorf("parsed invalid chain: %w", err)
	}

	return nil
}
