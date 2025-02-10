package dcatest

import (
	"crypto/x509"
	"fmt"
)

// TrustPool holds a collection of CAs
// and a certificate pool pointing at those CAs' certificates.
//
// This simplifies tests that need effective mTLS.
type TrustPool struct {
	CAs []*CA

	Pool *x509.CertPool
}

// NewTrustPool returns a new TrustPool from the given set of configs.
func NewTrustPool(cfgs ...CAConfig) (*TrustPool, error) {
	p := x509.NewCertPool()
	cas := make([]*CA, len(cfgs))
	for i, cfg := range cfgs {
		var err error
		cas[i], err = GenerateCA(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to generate CA at index %d", i)
		}

		p.AddCert(cas[i].Cert)
	}

	return &TrustPool{
		CAs:  cas,
		Pool: p,
	}, nil
}
