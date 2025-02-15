package dca

import (
	"crypto/x509"
	"sync"
)

// Pool is a collection of CA certificates.
type Pool struct {
	mu     sync.RWMutex
	cas    map[string]*x509.Certificate
	notify map[string]chan struct{}

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

		notify: make(map[string]chan struct{}),
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

	key := string(cert.Signature)
	delete(p.cas, key)
	p.lockedUpdateLazyCertPool()

	if ch := p.notify[key]; ch != nil {
		close(ch)
		delete(p.notify, key)
	}
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

	// After updating, if there were any pending notifications
	// corresponding to a now-missing certificate, then notify.
	for key, ch := range p.notify {
		if _, ok := p.cas[key]; ok {
			// Key still exists, don't notify.
			continue
		}

		// Key was removed, so notify and clear.
		close(ch)
		delete(p.notify, key)
	}
}

// NotifyRemoval returns a channel that is closed if and when
// the given CA is removed from the pool,
// either directly through a call to [(*Pool).RemoveCA]
// or indirectly by not being part of the new set in [(*Pool).UpdateCAs].
func (p *Pool) NotifyRemoval(cert *x509.Certificate) <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	// First, if we already have a notification for this certificate,
	// return that same channel.
	if ch := p.notify[string(cert.Signature)]; ch != nil {
		return ch
	}

	// Otherwise, confirm that the certificate is known.
	if _, ok := p.cas[string(cert.Signature)]; !ok {
		return nil
	}

	// The certificate is indeed known, so we can make the notification.
	ch := make(chan struct{})
	p.notify[string(cert.Signature)] = ch
	return ch
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
