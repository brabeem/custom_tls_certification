package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// mobile has stored somewhere is it paired or not
// if its unpaired it starts pairing for the first time
// Send the OTP and public key in the connection json {"otp":"","public_key":""}
// if its paired, present the self signed certificate as the certificate

type OTPMessage struct {
	OTP       string `json:"otp"`
	PublicKey string `json:"public_key"`
}

func main() {

	if !CheckIfCertAlreadyExists() {
		fmt.Println("📱 Starting first-time pairing...")
		DoFirstTimeParing()
		return
	}

	fmt.Println("📱 Using existing certificate for authentication...")
	PairUsingPublicKey()
}

func DoFirstTimeParing() {
	fmt.Println("=== First Time Pairing ===")
	CreateSelfSignedCertificate()

	// Load CA certificate to verify ZC server's certificate
	serverCaPool := x509.NewCertPool()
	serverCaPool.AppendCertsFromPEM(LoadCACertificate())
	fmt.Println("Added CA certificate to trust store for server verification")

	conf := &tls.Config{
		RootCAs: serverCaPool, // Verify ZC server's CA-signed certificate
	}

	fmt.Println("Connecting to ZC server for first-time pairing...")

	conn, err := tls.Dial("tcp", "localhost:8000", conf)
	if err != nil {
		log.Fatal("Failed to connect:", err)
	}

	defer conn.Close()
	fmt.Println("✅ Connected! ZC server certificate verified. Sending OTP and public key...")

	//send otp and public key
	tlsCert := LoadSelfSignedCertificates()
	myCert := tlsCert.Certificate[0]
	parsedCert, err := x509.ParseCertificate(myCert)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := x509.MarshalPKCS1PublicKey(parsedCert.PublicKey.(*rsa.PublicKey))
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)
	var message = OTPMessage{
		OTP:       "12345",
		PublicKey: publicKeyBase64, // Send as base64 instead of binary-to-string
	}
	messageData, err := json.Marshal(message)
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.Write(messageData)
	if err != nil {
		log.Fatal("Failed to send OTP:", err)
	}

	fmt.Println("✅ OTP and public key sent successfully!")
}

func PairUsingPublicKey() {
	fmt.Println("=== Authenticated Connection ===")
	myCert := LoadSelfSignedCertificates()

	// Load CA certificate to verify ZC server's certificate
	serverCaPool := x509.NewCertPool()
	serverCaPool.AppendCertsFromPEM(LoadCACertificate())
	fmt.Println("Added CA certificate to trust store for server verification")

	conf := &tls.Config{
		Certificates: []tls.Certificate{myCert}, // Present our self-signed certificate
		RootCAs:      serverCaPool,              // Verify ZC server's CA-signed certificate
	}

	fmt.Println("Connecting with self-signed certificate...")

	conn, err := tls.Dial("tcp", "localhost:8000", conf)
	if err != nil {
		log.Fatal("TLS handshake failed:", err)
	}

	fmt.Println("✅ TLS handshake successful! ZC server certificate verified, secure connection established.")
	defer conn.Close()

	// Keep connection alive briefly to see server response
	time.Sleep(1 * time.Second)
}

func CheckIfCertAlreadyExists() bool {
	_, certErr := os.Stat("mobile.cert")
	_, keyErr := os.Stat("mobile.pem")
	exists := certErr == nil && keyErr == nil

	if exists {
		fmt.Println("Found existing mobile certificate")
	}
	return exists
}

func CreateSelfSignedCertificate() {
	fmt.Println("Creating self-signed certificate...")
	key, err := rsa.GenerateKey(rand.Reader, 2048) // Use 2048 bits
	if err != nil {
		log.Fatal(err)
	}

	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Mobile-app"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // Changed to client auth
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

	err = os.WriteFile("mobile.pem", privateKeyBytes, 0600) // Changed to secure permissions
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("✅ Self-signed certificate created")
}

func LoadSelfSignedCertificates() tls.Certificate {
	fileContent, err := os.ReadFile("mobile.cert")
	if err != nil {
		log.Fatal(err)
	}

	CertBlock, _ := pem.Decode(fileContent)
	if CertBlock.Type != "CERTIFICATE" {
		log.Fatal("NO certificate block in the certificate")
	}

	fileContent, err = os.ReadFile("mobile.pem")
	if err != nil {
		log.Fatal(err)
	}

	PrivateBlock, _ := pem.Decode(fileContent)
	if PrivateBlock.Type != "RSA PRIVATE KEY" {
		log.Fatal("No private key in the certificate")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(PrivateBlock.Bytes)
	if err != nil {
		log.Fatal("Failed to parse private key:", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{CertBlock.Bytes},
		PrivateKey:  privateKey,
	}
}

func LoadCACertificate() []byte {
	fileContent, err := os.ReadFile("ca.cert")
	if err != nil {
		log.Fatal("Failed to load CA certificate:", err)
	}

	CertBlock, _ := pem.Decode(fileContent)
	if CertBlock == nil || CertBlock.Type != "CERTIFICATE" {
		log.Fatal("Invalid CA certificate format")
	}
	fmt.Println("✅ CA certificate loaded successfully")
	return pem.EncodeToMemory(CertBlock) // Return PEM-encoded bytes
}
