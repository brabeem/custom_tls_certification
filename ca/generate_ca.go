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

func main() {
	// Create a proper CA certificate with CA extensions
	createProperCA()
}

// Create a proper CA certificate with CA extensions
func createProperCA() {
	log.Println("=== Creating Proper CA Certificate ===")

	// Generate CA key pair
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Failed to generate CA key:", err)
	}

	// Create CA certificate template with proper CA extensions
	caCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Manufacturing-CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years for CA
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},

		// CRITICAL: These extensions make it a proper CA certificate
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,

		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	// Create self-signed CA certificate
	caCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&caCertTemplate,         // Certificate template
		&caCertTemplate,         // Self-signed (issuer = subject)
		&caPrivateKey.PublicKey, // CA public key
		caPrivateKey,            // CA private key (signer)
	)
	if err != nil {
		log.Fatal("Failed to create CA certificate:", err)
	}

	// Save CA certificate
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})
	err = os.WriteFile("ca.cert", caCertPEM, 0644)
	if err != nil {
		log.Fatal("Failed to save CA certificate:", err)
	}

	// Save CA private key
	caPrivateKeyDER := x509.MarshalPKCS1PrivateKey(caPrivateKey)
	caPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: caPrivateKeyDER,
	})
	err = os.WriteFile("ca.pem", caPrivateKeyPEM, 0600)
	if err != nil {
		log.Fatal("Failed to save CA private key:", err)
	}

	log.Println("✅ Proper CA certificate created successfully!")
	log.Println("   - Certificate: ca.cert")
	log.Println("   - Private key: ca.pem")
	log.Println("   - Subject: Manufacturing-CA")
	log.Println("   - Valid for: 10 years")
	log.Println("   - Can sign other certificates: ✅")
}
