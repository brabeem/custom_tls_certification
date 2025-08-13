package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
		fmt.Println("Go for first time pairing")
		DoFirstTimeParing()
		return
	}

	PairUsingPublicKey()
}

func DoFirstTimeParing() {
	serverCaPool := x509.NewCertPool()
	serverCaPool.AppendCertsFromPEM(LoadCACertificate())
	fmt.Println("Appending CA certificate to the conf......")
	conf := &tls.Config{
		RootCAs: serverCaPool,
	}

	fmt.Println("Dialing localhost:8000........")

	conn, err := tls.Dial("tcp", "localhost:8000", conf)
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()
	//send otp and public key
	CreateSelfSignedCertificate()
	tlsCert := LoadSelfSignedCertificates()
	myCert := tlsCert.Certificate[0]
	parsedCert, err := x509.ParseCertificate(myCert)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := x509.MarshalPKCS1PublicKey(parsedCert.PublicKey.(*rsa.PublicKey))
	var message = OTPMessage{
		OTP:       "12345",
		PublicKey: string(publicKey),
	}
	messageData, err := json.Marshal(message)
	if err != nil {
		log.Fatal(err)
	}
	conn.Write(messageData)
}

func PairUsingPublicKey() {
	myCert := LoadSelfSignedCertificates()
	serverCaPool := x509.NewCertPool()
	serverCaPool.AppendCertsFromPEM(LoadCACertificate())
	fmt.Println("Appending CA certificate to the conf......")

	conf := &tls.Config{
		Certificates: []tls.Certificate{myCert},
		RootCAs:      serverCaPool,
	}

	fmt.Println("Pairing using public key.......")

	conn, err := tls.Dial("tcp", "localhost:8000", conf)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("TLS handshake sucessfull: requests can be done securly now : closing connection.....")
	defer conn.Close()
}

func CheckIfCertAlreadyExists() bool {
	files, err := os.ReadDir(".")
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range files {
		if v.Name() == "mobile.cert" || v.Name() == "mobile.pem" {
			fmt.Println("Found mobile certificate")
			return true
		}
	}
	return false
}

func CreateSelfSignedCertificate() {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}

	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Mobile-app"},
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

	err = os.WriteFile("mobile.pem", privateKeyBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
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
		log.Fatal(err)
	}

	CertBlock, _ := pem.Decode(fileContent)
	if CertBlock.Type != "CERTIFICATE" {
		log.Fatal("NO certificate block in the certificate")
	}
	fmt.Println("CA certificate returned")
	return CertBlock.Bytes
}
