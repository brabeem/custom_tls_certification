package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// first generate self signed ca cert
// then generate self signed mobile cert
// then generate ca signed certificate for zc device

// COMMENTED OUT: Self-signed certificate generation (already created ca.cert, ca.pem, mobile.cert, mobile.pem)
func main() {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}

	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Brabeem-app"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	// encode the public key in the certificate and sign with the private key given , use the template above as the template for certificate
	newCert, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
		return
	}
	encodedCertificate := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCert,
	})

	err = os.WriteFile("mobile.cert", encodedCertificate, 0644)
	if err != nil {
		log.Fatal(err)
	}

	// also encode the private key
	encodedPrivateKey := x509.MarshalPKCS1PrivateKey(key)
	privateKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: encodedPrivateKey,
	})

	err = os.WriteFile("mobile.pem", privateKeyBytes, 0600)
	if err != nil {
		log.Fatal(err)
	}
}
