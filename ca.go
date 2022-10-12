package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"time"
)

type CAConfig struct {
	CommonName          string
	PermittedDNSDomains []string
	Expiry              time.Duration
}

func GenerateCA(config *CAConfig) (*CertificateKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	template, err := populateTemplate(config.CommonName, config.Expiry)
	if err != nil {
		return nil, err
	}
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign
	if len(config.PermittedDNSDomains) > 0 {
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = config.PermittedDNSDomains
	}
	certDer, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, err
	}
	certPem, privPem, err := encodeKeyPair(cert, priv)
	if err != nil {
		return nil, err
	}
	return &CertificateKeyPair{
		Certificate:    cert,
		PrivateKey:     priv,
		CertificatePem: certPem,
		PrivateKeyPem:  privPem,
	}, nil
}
