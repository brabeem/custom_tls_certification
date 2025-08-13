package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// for offline use
// generate a certificate for a zc-device and private and public keys
// generate a certificate for manufacturing CA
// for first time pairing ,
// verify the zc device cert
// tls config as verifyIfGiven
// if not passed tls handshake sucessfull
// otp send with public key stored if otp correct
// if cert passed , verify the cert, extract the public key , then check if it exists then only complete the handshake

// Simple state tracking - we'll determine state based on whether client certs are present
var ExistingData map[string]struct{}

const OTP = "12345"

func main() {
	myCert := LoadCertificateAndKey()
	ExistingData = make(map[string]struct{})
	config := tls.Config{
		Certificates:          []tls.Certificate{myCert},
		VerifyPeerCertificate: PeerVerification,
		ClientAuth:            tls.RequestClientCert,
	}

	fmt.Println("listening on localhost:8000")

	listener, err := tls.Listen("tcp", "localhost:8000", &config)
	if err != nil {
		log.Fatal(err)
	}

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleFunction(conn)
	}
}

func LoadCertificateAndKey() tls.Certificate {
	cert, err := tls.LoadX509KeyPair("zc.cert", "zc.pem")
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

func handleFunction(conn net.Conn) {
	//check the state if its FULLY_AUTHENTICATED then , any routes are accessible
	//if its NOT_FULLY_AUTHENTICATED then, only otp send route available
	//else nothing available
	defer conn.Close()

	// Determine state based on whether client presented certificates
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		fmt.Println("❌ Not a TLS connection")
		return
	}

	// Perform handshake to get connection state
	//TLS handshake is not yet done , its done lazily in the first read , write or if you call Handshake() explicitly
	err := tlsConn.Handshake()
	if err != nil {
		fmt.Printf("❌ TLS handshake failed: %v\n", err)
		return
	}

	connState := tlsConn.ConnectionState()
	var currentState string

	if len(connState.PeerCertificates) == 0 {
		currentState = "NOT_FULLY_AUTHENTICATED"
		fmt.Println("📱 First-time pairing - no client certificate presented")
	} else {
		// Check if the certificate is in our known list
		cert := connState.PeerCertificates[0]
		publicKeyBytes := x509.MarshalPKCS1PublicKey(cert.PublicKey.(*rsa.PublicKey))
		publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

		if _, exists := ExistingData[publicKeyBase64]; exists {
			currentState = "FULLY_AUTHENTICATED"
			fmt.Println("✅ Authenticated client - certificate found in known list")
		} else {
			fmt.Println("❌ Unknown certificate - access denied")
			return
		}
	}

	fmt.Printf("Reached handle function with state: %s\n", currentState)
	if currentState == "NOT_FULLY_AUTHENTICATED" {
		//you reach here during first pairing
		//you only get access to otp route
		DisplayOTP()
		//listen for OTP from the connection
		otpAndPublicKey := ListenForOTP(conn)
		if otpAndPublicKey.OTP == "" {
			fmt.Println("Failed to receive OTP - terminating connection")
			return
		}
		if otpAndPublicKey.OTP == OTP {
			//register the public key as known mobile app
			fmt.Println("✅ OTP verified! Registering device...")
			// The public key is already base64 encoded from mobile
			ExistingData[otpAndPublicKey.PublicKey] = struct{}{}
			AppendKnownLists("./known_lists.txt", otpAndPublicKey.PublicKey)
			fmt.Println("✅ Device paired successfully!")
		} else {
			//else terminate the connection
			fmt.Printf("❌ Invalid OTP received: %s\n", otpAndPublicKey.OTP)
			return
		}

	} else if currentState == "FULLY_AUTHENTICATED" {
		//you get access to everything
		// you reach here after first pairing
		//all the routing is done in this case
		fmt.Println("✅ FULLY_AUTHENTICATED - All routes accessible")
	} else {
		fmt.Println("❌ NEITHER FULLY AUTHENTICATED NOR NOT FULLY AUTHENTICATED")
		return
	}
}

func PeerVerification(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	fmt.Printf("\n🔍 PeerVerification called with %d certificates\n", len(rawCerts))

	if len(rawCerts) == 0 {
		fmt.Println("📱 Mobile client connecting for first-time pairing (no certificate presented)")
		// Allow connection without client certificate for first-time pairing
		return nil
	}

	fmt.Println("🔒 Mobile client connecting with certificate - verifying...")

	// if its not first time pairing
	clientCert := rawCerts[0]
	// first verify the self signed certificate if verified then extract the public key and check if it already exists
	parsedCert, err := x509.ParseCertificate(clientCert)
	if err != nil {
		fmt.Printf("❌ Failed to parse certificate: %v\n", err)
		return err
	}

	signatureBytes := parsedCert.Signature
	signatureAlg := parsedCert.SignatureAlgorithm
	rawTBScert := parsedCert.RawTBSCertificate
	var hash []byte
	switch signatureAlg {
	case x509.SHA256WithRSA:
		h := sha256.Sum256(rawTBScert)
		hash = h[:]
	default:
		fmt.Printf("Unsupported signature algorithm: %v\n", signatureAlg)
		return errors.New("unsupported signature algorithm")
	}

	fmt.Println("Going for certificate verification........")

	err = rsa.VerifyPKCS1v15(parsedCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash, signatureBytes)
	if err != nil {
		fmt.Printf("Certificate verification failed: %v\n", err)
		return errors.New("couldn't verify client certificate")
	}

	fmt.Println("Trying to load known_lists of the public key for this device.........")

	LoadKnownLists("./known_lists.txt")

	marshalledPublicKey := x509.MarshalPKCS1PublicKey(parsedCert.PublicKey.(*rsa.PublicKey))
	publicKeyBase64 := base64.StdEncoding.EncodeToString(marshalledPublicKey)

	if _, ok := ExistingData[publicKeyBase64]; !ok {
		fmt.Println("Unknown app trying to connect - connection failed")
		return errors.New("unknown app trying to connect")
	}

	fmt.Println("✅ Certificate verification successful - device is authorized")

	//can hit any routes
	AppendKnownLists("./known_lists.txt", publicKeyBase64)
	// State is now determined in handleFunction based on certificates
	return nil
}

func AppendKnownLists(filepath string, publicKey string) {
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to append to known lists: %v", err)
		return
	}

	defer file.Close()

	_, err = file.WriteString(publicKey + "\n")
	if err != nil {
		log.Printf("Failed to write to known lists: %v", err)
	}
}

func LoadKnownLists(filepath string) {
	existingData, err := os.ReadFile(filepath)
	if os.IsNotExist(err) {
		fmt.Println("Known lists file doesn't exist - starting fresh")
		return
	}
	if err != nil {
		log.Printf("Warning: Failed to load known lists: %v", err)
		return
	}
	lines := strings.Split(string(existingData), "\n")
	for _, line := range lines {
		if line != "" {
			ExistingData[line] = struct{}{}
		}
	}
	fmt.Printf("Loaded %d known devices\n", len(ExistingData))
}

func DisplayOTP() {
	fmt.Printf("OTP: %v\n", OTP)
}

func ListenForOTP(conn net.Conn) PublicKeyAndOTP {
	conn.SetReadDeadline(time.Now().Add(1 * time.Minute))
	var buffer = make([]byte, 4096) // Increased buffer size
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Failed to read OTP: %v", err)
		return PublicKeyAndOTP{}
	}
	buffer = buffer[:n]
	var output PublicKeyAndOTP
	err = json.Unmarshal(buffer, &output)
	if err != nil {
		log.Printf("Failed to unmarshal OTP: %v", err)
		return PublicKeyAndOTP{}
	}
	fmt.Printf("Received OTP: %s\n", output.OTP)
	return output
}

type PublicKeyAndOTP struct {
	PublicKey string `json:"public_key"`
	OTP       string `json:"otp"`
}
