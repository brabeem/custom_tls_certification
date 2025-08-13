package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	// Generate CA-signed certificate for ZC device
	generateCASignedZCCertificate()
}

// Generate CA-signed certificate for ZC device
func generateCASignedZCCertificate() {
	// Step 1: Load CA certificate and private key from parent directory
	caCert, caPrivateKey, err := loadCACredentials()
	if err != nil {
		log.Fatal("Failed to load CA credentials:", err)
	}

	// Step 2: Generate new key pair for ZC device
	zcPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Failed to generate ZC device key:", err)
	}

	// Step 3: Create certificate template for ZC device
	zcCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2), // Different serial number from CA
		Subject:      pkix.Name{CommonName: "ZC-Device"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // Server authentication
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	// Step 4: Sign ZC device certificate with CA private key
	// Important: Use CA cert as issuer, ZC template as subject
	zcCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&zcCertTemplate,         // Certificate to be created
		caCert,                  // CA certificate (issuer)
		&zcPrivateKey.PublicKey, // ZC device public key
		caPrivateKey,            // CA private key (signer)
	)
	if err != nil {
		log.Fatal("Failed to create CA-signed certificate:", err)
	}

	// Step 5: Save ZC device certificate
	zcCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: zcCertDER,
	})
	err = os.WriteFile("zc.cert", zcCertPEM, 0644)
	if err != nil {
		log.Fatal("Failed to save ZC certificate:", err)
	}

	// Step 6: Save ZC device private key
	zcPrivateKeyDER := x509.MarshalPKCS1PrivateKey(zcPrivateKey)
	zcPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: zcPrivateKeyDER,
	})
	err = os.WriteFile("zc.pem", zcPrivateKeyPEM, 0600)
	if err != nil {
		log.Fatal("Failed to save ZC private key:", err)
	}

	log.Println("✅ CA-signed ZC device certificate created successfully!")
	log.Println("   - Certificate: zc.cert")
	log.Println("   - Private key: zc.pem")
	log.Println("   - Signed by: CA certificate")

	// Verify the certificate chain
	verifyCertificateChain(zcCertDER, caCert)
}

// Load CA certificate and private key from parent directory
func loadCACredentials() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load CA certificate
	caCertPEM, err := os.ReadFile("ca.cert")
	if err != nil {
		return nil, nil, err
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Load CA private key
	caKeyPEM, err := os.ReadFile("ca.pem")
	if err != nil {
		return nil, nil, err
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil || caKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("✅ CA credentials loaded successfully")
	log.Printf("   - CA Subject: %s", caCert.Subject.CommonName)
	log.Printf("   - CA Serial Number: %s", caCert.SerialNumber.String())

	return caCert, caPrivateKey, nil
}

// Verify that the certificate chain is valid using manual verification
func verifyCertificateChain(zcCertDER []byte, caCert *x509.Certificate) {
	// Parse ZC certificate
	zcCert, err := x509.ParseCertificate(zcCertDER)
	if err != nil {
		log.Printf("❌ Failed to parse ZC certificate for verification: %v", err)
		return
	}

	log.Println("=== Manual Certificate Chain Verification ===")

	// Step 1: Basic certificate information
	log.Printf("ZC Certificate Subject: %s", zcCert.Subject.CommonName)
	log.Printf("ZC Certificate Issuer: %s", zcCert.Issuer.CommonName)
	log.Printf("CA Certificate Subject: %s", caCert.Subject.CommonName)

	// Step 2: Check if the ZC certificate was issued by our CA
	if zcCert.Issuer.String() != caCert.Subject.String() {
		log.Printf("❌ Certificate issuer mismatch!")
		log.Printf("   Expected issuer: %s", caCert.Subject.String())
		log.Printf("   Actual issuer: %s", zcCert.Issuer.String())
		return
	}
	log.Println("✅ Certificate issuer matches CA subject")

	// Step 3: Check certificate validity period
	now := time.Now()
	if now.Before(zcCert.NotBefore) {
		log.Printf("❌ Certificate not yet valid (starts: %v)", zcCert.NotBefore)
		return
	}
	if now.After(zcCert.NotAfter) {
		log.Printf("❌ Certificate expired (ended: %v)", zcCert.NotAfter)
		return
	}
	log.Println("✅ Certificate is within valid time period")

	// Step 4: Verify the digital signature manually
	err = manuallyVerifySignature(zcCert, caCert)
	if err != nil {
		log.Printf("❌ Digital signature verification failed: %v", err)
		return
	}
	log.Println("✅ Digital signature verification successful")

	// Step 5: Check CA certificate can sign certificates
	if !caCert.IsCA {
		log.Printf("❌ CA certificate is not marked as CA (IsCA=false)")
		return
	}
	if (caCert.KeyUsage & x509.KeyUsageCertSign) == 0 {
		log.Printf("❌ CA certificate cannot sign certificates (missing CertSign key usage)")
		return
	}
	log.Println("✅ CA certificate is authorized to sign certificates")

	log.Println("🎉 Manual certificate chain verification completely successful!")
	log.Printf("   Certificate chain: %s ← %s", zcCert.Subject.CommonName, caCert.Subject.CommonName)
}

// Manually verify the certificate signature using the CA's public key
func manuallyVerifySignature(cert *x509.Certificate, caCert *x509.Certificate) error {
	// Get the CA's public key
	caPublicKey, ok := caCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("CA certificate does not contain RSA public key")
	}

	// Get the certificate's signature algorithm
	var hashFunc crypto.Hash
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		hashFunc = crypto.SHA256
	case x509.SHA1WithRSA:
		hashFunc = crypto.SHA1
	case x509.SHA512WithRSA:
		hashFunc = crypto.SHA512
	default:
		return fmt.Errorf("unsupported signature algorithm: %v", cert.SignatureAlgorithm)
	}

	// Hash the TBS (To Be Signed) certificate data
	hasher := hashFunc.New()
	hasher.Write(cert.RawTBSCertificate)
	hash := hasher.Sum(nil)

	// Verify the signature using RSA PKCS1v15
	err := rsa.VerifyPKCS1v15(caPublicKey, hashFunc, hash, cert.Signature)
	if err != nil {
		return fmt.Errorf("RSA signature verification failed: %v", err)
	}

	log.Printf("✅ Signature algorithm: %v", cert.SignatureAlgorithm)
	log.Printf("✅ Hash function: %v", hashFunc)
	log.Printf("✅ Signature length: %d bytes", len(cert.Signature))

	return nil
}
