package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log"
	"os"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
		return
	}

	publicKey := key.Public()
	publicKeyMarshalled, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println(string(publicKeyMarshalled))
	PEMEncodedPublicKey := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: map[string]string{"Subject": "Brabeem public key"},
		Bytes:   publicKeyMarshalled,
	})

	filePath := "/Users/brabeemsapkota/Documents/codeduo/ssl/public_key.pem"
	privateKeyMarshalled := x509.MarshalPKCS1PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}

	PEMEncodedPrivateKey := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Subject": "Brabeem private key"},
		Bytes:   privateKeyMarshalled,
	})

	var allEncodings []byte
	allEncodings = append(allEncodings, PEMEncodedPrivateKey...)
	allEncodings = append(allEncodings, PEMEncodedPublicKey...)
	err = os.WriteFile(filePath, allEncodings, fs.ModeAppend)
	if err != nil {
		log.Fatal(err)
	}

	// here i want to create a certificate manually ,
	CreateManualCertificate(key.PublicKey, *key, "BRABEEM")
	VerifyManuallyCreatedCertificate("./my_cert.cert")
}

type ManualCertificate struct {
	PublicKey []byte
	Subject   []byte
	Signature []byte
}

func CreateManualCertificate(publicKey rsa.PublicKey, privateKey rsa.PrivateKey, subject string) {
	marshalledPublicKey := x509.MarshalPKCS1PublicKey(&publicKey)

	publicKeyBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshalledPublicKey,
	})

	subjectBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "SUBJECT",
		Bytes: []byte(subject),
	})
	allBlocks := []byte{}
	allBlocks = append(allBlocks, publicKeyBlock...)
	allBlocks = append(allBlocks, subjectBlock...)
	hasedAllBlocks := sha256.Sum256(append(marshalledPublicKey, []byte(subject)...))
	signature, err := rsa.SignPKCS1v15(rand.Reader, &privateKey, crypto.SHA256, hasedAllBlocks[:])
	if err != nil {
		log.Fatal(err)
	}
	encodedSignature := pem.EncodeToMemory(&pem.Block{
		Type:  "SIGNATURE",
		Bytes: signature,
	})

	allBlocks = append(allBlocks, encodedSignature...)

	err = os.WriteFile("my_cert.cert", allBlocks, fs.ModeAppend)
	if err != nil {
		log.Fatal(err)
	}
}

func VerifyManuallyCreatedCertificate(filePath string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
		return
	}
	blocks := ParsePEMBlocks(content)
	subject := blocks["SUBJECT"]
	publicKey := blocks["PUBLIC KEY"]
	signature := blocks["SIGNATURE"]
	publicKeyParsed, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}
	hashedData := sha256.Sum256(append(publicKey[:], subject...))
	err = rsa.VerifyPKCS1v15(publicKeyParsed, crypto.SHA256, hashedData[:], signature)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully verified certificate")
}

func ParsePEMBlocks(content []byte) map[string][]byte {
	blocks := make(map[string][]byte)
	block, rest := pem.Decode(content)
	for block != nil {
		blocks[string(block.Type)] = block.Bytes
		content = rest
		block, rest = pem.Decode(content)
	}
	return blocks
}
