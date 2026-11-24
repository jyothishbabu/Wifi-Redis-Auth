#!/usr/bin/env bash
# TESTING ONLY: issue a client cert from the private CA to prove EAP-TLS works
# before Cloud PKI is ready. Production laptops get certs from Intune Cloud PKI.
set -euo pipefail
cd "$(dirname "$0")/.."
NAME="${1:-TEST-LAPTOP}"
CA_DIR=certs/private-ca
OUT=certs/test-clients
mkdir -p $OUT
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n' > $OUT/c.ext
openssl genrsa -out $OUT/$NAME.key 2048
openssl req -new -key $OUT/$NAME.key -subj "/CN=$NAME" -out $OUT/$NAME.csr
openssl x509 -req -in $OUT/$NAME.csr -CA $CA_DIR/ca.pem -CAkey $CA_DIR/ca.key \
  -CAcreateserial -days 30 -sha256 -extfile $OUT/c.ext -out $OUT/$NAME.pem
rm -f $OUT/$NAME.csr $OUT/c.ext
echo "Issued $OUT/$NAME.pem (valid 30 days)"
