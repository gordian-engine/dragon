package dcert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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

	return Chain{
		Leaf:         certs[0],
		Intermediate: slices.Clip(certs[1 : len(certs)-1]),
		Root:         certs[len(certs)-1],
	}, nil
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
