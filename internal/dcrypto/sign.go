package dcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

func SignMessageWithTLSCert(
	msg []byte,
	cert tls.Certificate,
) ([]byte, error) {
	if cert.Leaf == nil {
		panic(errors.New(
			"BUG: attempted to sign with Certificate missing a leaf; use x509.ParseCertificate to set it",
		))
	}

	switch k := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		hasher := getRSAHasher(cert.Leaf.SignatureAlgorithm)
		h := hasher.New()
		h.Write(msg)
		hash := h.Sum(nil)
		return rsa.SignPKCS1v15(cryptorand.Reader, k, hasher, hash[:])

	case ed25519.PrivateKey:
		return ed25519.Sign(k, msg), nil

	case *ecdsa.PrivateKey:
		hasher := getCurveHasher(k.Curve)
		h := hasher.New()
		h.Write(msg)
		hash := h.Sum(nil)
		return ecdsa.SignASN1(cryptorand.Reader, k, hash[:])

	default:
		panic(fmt.Errorf("unrecognized TLS private key type %T", k))
	}
}

func getRSAHasher(algo x509.SignatureAlgorithm) crypto.Hash {
	switch algo {
	case x509.SHA256WithRSA:
		return crypto.SHA256
	case x509.SHA384WithRSA:
		return crypto.SHA384
	case x509.SHA512WithRSA:
		return crypto.SHA512
	default:
		panic(fmt.Errorf(
			"BUG: unknown signature algorithm %v for RSA private key", algo,
		))
	}
}

func getCurveHasher(curve elliptic.Curve) crypto.Hash {
	switch curve {
	case elliptic.P224(), elliptic.P256():
		return crypto.SHA256
	case elliptic.P384():
		return crypto.SHA384
	case elliptic.P521():
		return crypto.SHA512
	default:
		panic(fmt.Errorf("BUG: unknown curve %v for ECDSA private key", curve))
	}
}

func VerifySignatureWithTLSCert(
	msg []byte,
	cert *x509.Certificate,
	sig []byte,
) error {
	// TODO: should this switch to cert.CheckSignature?
	// I'm not sure about the SignatureAlgorithm part of that method.

	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		hasher := getRSAHasher(cert.SignatureAlgorithm)
		h := hasher.New()
		h.Write(msg)
		hash := h.Sum(nil)
		return rsa.VerifyPKCS1v15(k, hasher, hash, sig)

	case ed25519.PublicKey:
		if !ed25519.Verify(k, msg, sig) {
			return errors.New("invalid ed25519 signature")
		}
		return nil

	case *ecdsa.PublicKey:
		hasher := getCurveHasher(k.Curve)
		h := hasher.New()
		h.Write(msg)
		hash := h.Sum(nil)
		if !ecdsa.VerifyASN1(k, hash, sig) {
			return errors.New("invalid ecdsa signature")
		}
		return nil

	default:
		panic(fmt.Errorf("unrecognized TLS public key type %T", k))
	}
}
