package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
var state string
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
	fmt.Println("reached handle function")
	if state == "NOT_FULLY_AUTHENTICATED" {
		//you reach here during first pairing
		//you only get access to otp route
		DisplayOTP()
		//listen for OTP from the connection
		otpAndPublicKey := ListenForOTP(conn)
		if otpAndPublicKey.OTP == OTP {
			//register the public key as known mobile app
			ExistingData[otpAndPublicKey.PublicKey] = struct{}{}
			AppendKnownLists("./known_lists.txt", otpAndPublicKey.PublicKey)
		} else {
			//else terminate the connection
			return
		}

	} else if state == "FULLY_AUTHENTICATED" {
		//you get access to everything
		// you reach here after first pairing
		//all the routing is done in this case
		fmt.Println("FULLY_AUTHENTICATED")
	} else {
		fmt.Println("NEITHER FULLY AUTHENTICATED NOR NOT FULLY AUTHENTICATED........")
		return
	}
}

func PeerVerification(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		fmt.Println("An app is trying to pair for the first time")
		//only expose OTP receiving route at this state
		state = "NOT_FULLY_AUTHENTICATED"
		return nil
	}

	fmt.Println("Going for Public key connection........")

	// if its not first time pairing
	clientCert := rawCerts[0]
	// first verify the self signed certificate if verified then extract the public key and check if it already exists
	parsedCert, err := x509.ParseCertificate(clientCert)
	if err != nil {
		log.Fatal(err)
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
		return errors.New("Unsupported signature alg")
	}

	fmt.Println("Going for certificate verification........")

	err = rsa.VerifyPKCS1v15(parsedCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash, signatureBytes)
	if err != nil {
		log.Fatal(err)
		return errors.New("Couldn't verify client")
	}

	fmt.Println("Trying to load known_lists of the public key for this device.........")

	LoadKnownLists("./known_lists.txt")

	marshalledPublicKey := x509.MarshalPKCS1PublicKey(parsedCert.PublicKey.(*rsa.PublicKey))
	if _, ok := ExistingData[string(marshalledPublicKey)]; !ok {
		fmt.Println("Unknown app trying to connect conection failed")
		return errors.New("Unknown app trying to connect")
	}

	//can hit any routes
	AppendKnownLists("./known_lists.txt", string(marshalledPublicKey))
	state = "FULLY_AUTHENTICATED"
	return nil
}

func AppendKnownLists(filepath string, publicKey string) {
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	_, err = file.WriteString(publicKey + "\n")
	if err != nil {
		log.Fatal(err)
	}
}

func LoadKnownLists(filepath string) {
	existingData, err := os.ReadFile(filepath)
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(existingData), "\n")
	for _, line := range lines {
		if line != "" {
			ExistingData[line] = struct{}{}
		}
	}
}

func DisplayOTP() {
	fmt.Println("OTP: %v", OTP)
}

func ListenForOTP(conn net.Conn) PublicKeyAndOTP {
	conn.SetReadDeadline(time.Now().Add(1 * time.Minute))
	var buffer = make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}
	buffer = buffer[:n]
	var output PublicKeyAndOTP
	err = json.Unmarshal(buffer, &output)
	if err != nil {
		log.Fatal(err)
	}
	return output
}

type PublicKeyAndOTP struct {
	PublicKey string `json:"public_key"`
	OTP       string `json:"otp"`
}
