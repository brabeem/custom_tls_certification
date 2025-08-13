# TLS Handshaking System for Mobile-ZC Device Communication

A Dummy TLS-based secure communication system demonstration implementing certificate-based authentication between mobile clients and ZC (Zero Configuration) devices.

## 🏗️ Architecture Overview

This system implements a secure pairing and communication protocol:

- **ZC Device (Server)**: Uses CA-signed certificate, validates mobile self-signed certificates
- **Mobile Client**: Creates self-signed certificates, validates ZC's CA-signed certificate
- **Two-phase Flow**: First-time pairing (OTP-based) → Authenticated communication

## 📁 Project Structure

```
root/
├── ca/
│   └── generate_ca.go              # Generate Manufacturing CA certificate
├── ca-signed/
│   └── generate_zc_cert.go         # Generate CA-signed ZC device certificate
├── tlsHandshaking/
│   ├── zc/
│   │   └── zcdevice.go            # ZC device server with TLS handshaking
│   └── mobile/
│       └── mobile.go              # Mobile client with pairing logic
├── manual/
│   └── manual_cert.go             # Manual certificate generation examples
├── mobile/
│   └── mobile.go                  # Standalone mobile certificate generator
├── ca.cert                        # Manufacturing CA certificate (PEM)
├── ca.pem                         # Manufacturing CA private key (PEM)
├── zc.cert                        # ZC device certificate (CA-signed, PEM)
├── zc.pem                         # ZC device private key (PEM)
├── mobile.cert                    # Mobile client certificate (self-signed, PEM)
├── mobile.pem                     # Mobile client private key (PEM)
├── known_lists.txt                # Stored trusted mobile public keys (base64)
└── go.mod                         # Go module definition
```

## 🚀 Quick Start

### Prerequisites

- Go 1.24.2 or later
- OpenSSL (optional, for certificate inspection)

### Step 1: Generate Certificate Infrastructure

```bash
cd /path/to/root

# 1. Generate Manufacturing CA certificate
go run ca/generate_ca.go

# 2. Generate CA-signed certificate for ZC device
go run ca-signed/generate_zc_cert.go
```

**Expected Output:**
```
✅ CA credentials loaded successfully
   - CA Subject: Manufacturing-CA
✅ CA-signed ZC device certificate created successfully!
🎉 Manual certificate chain verification completely successful!
```

### Step 2: Start ZC Device Server

```bash
# Start the ZC device server (runs on localhost:8000)
go run tlsHandshaking/zc/zcdevice.go
```

**Expected Output:**
```
listening on localhost:8000
```

### Step 3: First-Time Mobile Pairing

In a new terminal:

```bash
# Remove any existing mobile certificates to simulate first-time pairing
rm -f mobile.cert mobile.pem

# Run mobile client for first-time pairing
go run tlsHandshaking/mobile/mobile.go
```

**Expected Mobile Output:**
```
📱 Starting first-time pairing...
=== First Time Pairing ===
Creating self-signed certificate...
✅ Self-signed certificate created
✅ CA certificate loaded successfully
Added CA certificate to trust store for server verification
Connecting to ZC server for first-time pairing...
✅ Connected! ZC server certificate verified. Sending OTP and public key...
✅ OTP and public key sent successfully!
```

**Expected ZC Server Output:**
```
🔍 PeerVerification called with 0 certificates
📱 Mobile client connecting for first-time pairing (no certificate presented)
📱 First-time pairing - no client certificate presented
Reached handle function with state: NOT_FULLY_AUTHENTICATED
OTP: 12345
Received OTP: 12345
✅ OTP verified! Registering device...
✅ Device paired successfully!
```

### Step 4: Authenticated Connection

Run the mobile client again (now with existing certificates):

```bash
go run tlsHandshaking/mobile/mobile.go
```

**Expected Mobile Output:**
```
Found existing mobile certificate
📱 Using existing certificate for authentication...
=== Authenticated Connection ===
✅ CA certificate loaded successfully
Added CA certificate to trust store for server verification
Connecting with self-signed certificate...
✅ TLS handshake successful! ZC server certificate verified, secure connection established.
```

**Expected ZC Server Output:**
```
🔍 PeerVerification called with 1 certificates
🔒 Mobile client connecting with certificate - verifying...
Going for certificate verification........
Trying to load known_lists of the public key for this device.........
Loaded 1 known devices
✅ Certificate verification successful - device is authorized
✅ Authenticated client - certificate found in known list
Reached handle function with state: FULLY_AUTHENTICATED
✅ FULLY_AUTHENTICATED - All routes accessible
```

## 🔐 Security Flow Explained

### First-Time Pairing Flow

1. **Mobile**: Creates self-signed certificate, connects without presenting client cert
2. **ZC**: Validates mobile's connection using server's CA-signed certificate
3. **Mobile**: Sends OTP + public key over secure TLS channel
4. **ZC**: Validates OTP (12345), stores public key in known_lists.txt
5. **Result**: Mobile is now "paired" and trusted

### Authenticated Connection Flow

1. **Mobile**: Presents self-signed certificate during TLS handshake
2. **ZC**: Manually verifies certificate signature and checks public key against known_lists.txt
3. **ZC**: If found, connection is FULLY_AUTHENTICATED
4. **Result**: Mobile has access to all ZC device routes/functionality

### Certificate Validation Details

**ZC Server Certificate (CA-signed)**:
- Signed by Manufacturing CA
- Uses `ExtKeyUsageServerAuth` (server authentication)
- Validated by mobile using CA certificate

**Mobile Certificate (Self-signed)**:
- Self-signed with same key pair
- Uses `ExtKeyUsageClientAuth` (client authentication)  
- Manually validated by ZC using signature verification + known key list

