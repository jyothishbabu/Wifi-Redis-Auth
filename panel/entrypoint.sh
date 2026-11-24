#!/bin/sh
# Serve the panel over HTTPS only. The panel issues its own certificate during
# setup (data/panel/tls/); until then a temporary self-signed one is used.
set -e
mkdir -p /data/panel/tls
CERT=/data/panel/tls/panel.pem KEY=/data/panel/tls/panel.key
if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
  CERT=/data/panel/tls/bootstrap.pem KEY=/data/panel/tls/bootstrap.key
  [ -s "$CERT" ] || python3 - "$CERT" "$KEY" <<'PY'
import sys, datetime as dt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
k = ec.generate_private_key(ec.SECP256R1())
n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wifi-redis-panel-setup")])
now = dt.datetime.now(dt.timezone.utc)
c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
     .serial_number(x509.random_serial_number()).not_valid_before(now)
     .not_valid_after(now + dt.timedelta(days=397)).sign(k, hashes.SHA256()))
open(sys.argv[1], "wb").write(c.public_bytes(serialization.Encoding.PEM))
open(sys.argv[2], "wb").write(k.private_bytes(serialization.Encoding.PEM,
     serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
PY
  chmod 600 "$KEY"
fi
# One worker: login throttling and file locking live in this process.
exec gunicorn --workers 1 --threads 8 --bind 0.0.0.0:8443 \
  --certfile "$CERT" --keyfile "$KEY" --access-logfile - app:app
