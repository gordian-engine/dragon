package dca

import (
	"crypto/x509"
	"sync"
)

// Pool is a collection of CA certificates.
type Pool struct {
	mu  sync.RWMutex
	cas map[string]*x509.Certificate

	lazyCertPool func() *x509.CertPool
}

// NewPool returns a new pool that does not contain any trusted certificates yet.
func NewPool() *Pool {
	return NewPoolFromCerts(nil)
}

// NewPoolFromCerts returns a new pool trusting the given certificates.
func NewPoolFromCerts(certs []*x509.Certificate) *Pool {
	p := &Pool{
		cas: make(map[string]*x509.Certificate, len(certs)),
	}

	for _, cert := range certs {
		p.cas[string(cert.Signature)] = cert
	}

	// We don't actually hold the lock here,
	// but there is no possible contention before we return it anyway.
	p.lockedUpdateLazyCertPool()

	return p
}

// CertPool returns the underlying certificate pool.
// This pool is shared until p's CA set changes,
// so the returned value must not be modified.
func (p *Pool) CertPool() *x509.CertPool {
	return p.lazyCertPool()
}

// AddCA adds a single CA certificate to the pool.
// Prefer to use [(*Pool).UpdateCAs].
func (p *Pool) AddCA(cert *x509.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cas[string(cert.Signature)] = cert
	p.lockedUpdateLazyCertPool()
}

// RemoveCA removes the given certificate from the pool.
// Prefer to use [(*Pool).UpdateCAs].
func (p *Pool) RemoveCA(cert *x509.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.cas, string(cert.Signature))
	p.lockedUpdateLazyCertPool()
}

// UpdateCAs replaces the entire CA set with the given certs.
func (p *Pool) UpdateCAs(certs []*x509.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()

	clear(p.cas)
	for _, cert := range certs {
		p.cas[string(cert.Signature)] = cert
	}

	p.lockedUpdateLazyCertPool()
}

func (p *Pool) lockedUpdateLazyCertPool() {
	p.lazyCertPool = sync.OnceValue(func() *x509.CertPool {
		cp := x509.NewCertPool()
		for _, ca := range p.cas {
			cp.AddCert(ca)
		}
		return cp
	})
}
