package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func HiddenTLSCert() ([]byte, []byte, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Country:      []string{"The Moon"},
			Organization: []string{"Aliens"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}
	pub := &priv.PublicKey
	cert_b, err := x509.CreateCertificate(rand.Reader, cert, nil, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	priv_b := x509.MarshalPKCS1PrivateKey(priv)
	return cert_b, priv_b, nil
}
