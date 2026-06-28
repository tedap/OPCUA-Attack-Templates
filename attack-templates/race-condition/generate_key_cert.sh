#!/bin/bash
set -e

# Usage check
if [ $# -ne 1 ]; then
    echo "Usage: $0 <server|client>"
    exit 1
fi

ROLE="$1"
KEY_PEM="${ROLE}_key.pem"
CERT_PEM="${ROLE}_cert.pem"
KEY_DER="${ROLE}_key.der"
CERT_DER="${ROLE}_cert.der"
CONFIG_FILE="rsa_cert.cnf"

# Check config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: $CONFIG_FILE not found. Create it with the desired SAN and subject."
    exit 1
fi

echo "Generating RSA 2048-bit private key for $ROLE..."
openssl genrsa -out "$KEY_PEM" 2048

echo "Creating self-signed certificate for $ROLE with SAN from $CONFIG_FILE..."
openssl req -new -x509 -key "$KEY_PEM" -sha256 -days 365 -out "$CERT_PEM" -config "$CONFIG_FILE"

echo "Converting certificate to DER format..."
openssl x509 -in "$CERT_PEM" -outform DER -out "$CERT_DER"

echo "Converting private key to DER format..."
openssl rsa -in "$KEY_PEM" -outform DER -out "$KEY_DER"

echo "Cleaning up temporary PEM files..."
rm "$KEY_PEM" "$CERT_PEM"

echo "RSA certificate and key generated successfully for $ROLE:"
echo "  Private key (DER): $KEY_DER"
echo "  Certificate (DER): $CERT_DER"