package dcatest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// KeyType indicates which key type is used
// in a CA or leaf.
type KeyType int

const (
	UnspecifiedKeyType KeyType = iota
	RSAKeyType
	ECDSAKeyType
	Ed25519KeyType
)

// CAConfig is the configuration for generating a CA.
type CAConfig struct {
	KeyType   KeyType
	KeyParams any // Dependent on the key type.

	ValidFor time.Duration

	// Optional subject for CA template,
	// will use a reasonable default otherwise.
	Subject *pkix.Name
}

// LeafConfig is the configuration for generating a Leaf.
type LeafConfig struct {
	KeyType   KeyType // If blank, will default to CA's KeyType.
	KeyParams any     // Dependent on the key type.

	ValidFor time.Duration

	// Optional subject for CA template,
	// will use a reasonable default otherwise.
	Subject *pkix.Name

	DNSNames []string
}

// CA is a certificate authority.
type CA struct {
	// Unclear if PEM is useful here,
	// but we'll include it for now.
	CertPEM []byte
	KeyPEM  []byte

	Cert *x509.Certificate

	KeyType         KeyType
	PubKey, PrivKey any

	// Counter for the next generated certificate.
	prevSerial int64
}

// LeafCert is a certificate generated from a [CA].
// This is the actual certificate presented to a server or client
// when establishing a TLS connection.
type LeafCert struct {
	CertPEM []byte
	KeyPEM  []byte

	Cert *x509.Certificate

	KeyType         KeyType
	PubKey, PrivKey any
}

// FastConfig returns a config that is intended to be minimally resource intensive,
// making it suitable for heavier use in test.
func FastConfig() CAConfig {
	return CAConfig{
		KeyType:  Ed25519KeyType,
		ValidFor: time.Hour,
	}
}

// GenerateCA generates a new CA from the given config.
func GenerateCA(cfg CAConfig) (*CA, error) {
	var pubKey, privKey any

	switch cfg.KeyType {
	case Ed25519KeyType:
		var err error
		pubKey, privKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
		}
	default:
		panic(fmt.Errorf("TODO: handle key type %v", cfg.KeyType))
	}

	validFor := cfg.ValidFor
	if validFor == 0 {
		validFor = 24 * time.Hour
	}

	var name pkix.Name
	if cfg.Subject == nil {
		name = pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA Root",
		}
	} else {
		name = *cfg.Subject
	}
	template := &x509.Certificate{
		// This is fixed at 1, but the CA type has a counter for subsequent serial numbers.
		SerialNumber: big.NewInt(1),

		Subject:   name,
		NotBefore: time.Now().Add(-15 * time.Second),
		NotAfter:  time.Now().Add(validFor),

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			// The CA needs every extended key usage that the leaf certificate will have.
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	derBytes, err := x509.CreateCertificate(nil, template, template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}); err != nil {
		return nil, fmt.Errorf("failed to encode certificate: %w", err)
	}
	certPEM := bytes.Clone(buf.Bytes())

	// Parse the actual certificate from the DER.
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from DER: %w", err)
	}

	buf.Reset()
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err := pem.Encode(&buf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}); err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}
	keyPEM := buf.Bytes() // Don't need to clone this, due to last use of buf.

	return &CA{
		// Unclear if these PEM values are actually useful, yet.
		CertPEM: certPEM,
		KeyPEM:  keyPEM,

		Cert: cert,

		PubKey:  pubKey,
		PrivKey: privKey,
		KeyType: cfg.KeyType,

		prevSerial: 1,
	}, nil
}

// CreateLeafCert generates a new leaf certificate from this CA.
func (ca *CA) CreateLeafCert(cfg LeafConfig) (*LeafCert, error) {
	if len(cfg.DNSNames) == 0 {
		panic(errors.New("BUG: LeafConfig must contain at least one DNS name"))
	}

	keyType := cfg.KeyType
	if keyType == UnspecifiedKeyType {
		keyType = ca.KeyType
	}

	var pubKey, privKey any
	switch keyType {
	case Ed25519KeyType:
		var err error
		pubKey, privKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
		}

	default:
		panic(fmt.Errorf("TODO: handle key type %v", cfg.KeyType))
	}

	validFor := cfg.ValidFor
	if validFor == 0 {
		validFor = 24 * time.Hour
	}

	var name pkix.Name
	if cfg.Subject == nil {
		name = pkix.Name{
			Organization: []string{"Test Leaf Cert"},
			CommonName:   cfg.DNSNames[0],
		}
	} else {
		name = *cfg.Subject
	}

	ca.prevSerial++

	template := &x509.Certificate{
		SerialNumber: big.NewInt(ca.prevSerial),
		Subject:      name,
		NotBefore:    time.Now().Add(-15 * time.Second),
		NotAfter:     time.Now().Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames: cfg.DNSNames,

		// This is only intended to be used in local tests (for now at least),
		// so just hardcode localhost for the IP address.
		// Without this, you would get an error like:
		// x509: cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs.
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},

		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(nil, template, ca.Cert, pubKey, ca.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the actual certificate from the DER.
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from DER: %w", err)
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}); err != nil {
		return nil, fmt.Errorf("failed to encode certificate: %w", err)
	}
	certPEM := bytes.Clone(buf.Bytes())

	buf.Reset()
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err := pem.Encode(&buf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}); err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}
	keyPEM := buf.Bytes() // Don't need to clone this, due to last use of buf.

	return &LeafCert{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Cert:    cert,
		PubKey:  pubKey,
		PrivKey: privKey,
		KeyType: keyType,
	}, nil
}
