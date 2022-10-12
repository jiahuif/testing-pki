package pki

import "crypto/x509"

func NewCertPoolFromCA(ca *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool
}
