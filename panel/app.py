"""Wi-Fi RADIUS admin panel.

Everything is configured here: admin account, SSID, offices (RADIUS clients),
certificates, block list and debug logging. The panel writes the RADIUS config
into data/config and asks the radius container to reload; radius applies it only
if `radiusd -C` passes. No .env file is used.
"""
import csv
import datetime as dt
import hashlib
import hmac
import io
import ipaddress
import json
import os
import plistlib
import re
import secrets
import signal
import threading
import time
import uuid
from functools import wraps

from installers import mac_profile, windows_installer
from intune import IntuneCache

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import (Flask, Response, abort, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

DATA = os.environ.get("PANEL_DATA", "/data")
P_DIR, CFG_DIR = f"{DATA}/panel", f"{DATA}/config"
LOG_DIR, CTL_DIR = f"{DATA}/logs", f"{DATA}/control"
CA_DIR, TLS_DIR, TRUST_DIR = f"{P_DIR}/ca", f"{P_DIR}/tls", f"{P_DIR}/trusted"
DEVCA_DIR = f"{P_DIR}/deviceca"
DEVICES = f"{P_DIR}/devices.json"
SETTINGS, BLOCKED, AUDIT = f"{P_DIR}/settings.json", f"{P_DIR}/blocked.json", f"{P_DIR}/audit.log"
SETUP_CODE = f"{P_DIR}/setup-code"

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
DEVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SSID_RE = re.compile(r"^[A-Za-z0-9 _.-]{1,32}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
# No quotes, backslash, $, braces or spaces: they would break clients.conf.
SECRET_RE = re.compile(r"^[A-Za-z0-9!#%&()*+,./:;<=>?@^_|~-]{16,128}$")
FIELDS = ["ts", "result", "src", "office", "user", "cn", "mac", "nas", "ssid", "ap", "reason"]
SESSION_IDLE = 30 * 60
MAX_FAILS, LOCK_SECS = 5, 15 * 60
LINK_DAYS, CERT_DAYS = 7, 365
MAX_UPLOAD = 256 * 1024

lock = threading.Lock()
fails = {}  # ip -> [count, first_fail_ts]
for d in (P_DIR, CFG_DIR, CTL_DIR, CA_DIR, TLS_DIR, TRUST_DIR, DEVCA_DIR):
    os.makedirs(d, exist_ok=True)


# ================================================================ files
def atomic_write(path, data, mode=0o644):
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def audit(action, detail=""):
    with open(AUDIT, "a") as f:
        f.write(f"{int(time.time())}\t{session.get('user', '-')}\t{client_ip()}\t{action}\t{detail}\n")


def gen_secret():
    abc = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(abc) for _ in range(32))


# ================================================================ settings
DEFAULTS = {"configured": False, "ssid": "", "admin": {"user": "", "hash": ""}, "offices": [],
            "extra_ips": [], "debug": False, "server_name": "radius.wifi.internal", "panel_host": "",
            "intune": {}, "app_name": "WiFi RADIUS Authenticator"}


def get_settings():
    s = load_json(SETTINGS, None)
    if s is None:
        s = json.loads(json.dumps(DEFAULTS))
        s["local_secret"] = gen_secret()
        atomic_write(SETTINGS, json.dumps(s, indent=2), 0o600)
    for k, v in DEFAULTS.items():
        s.setdefault(k, v)
    for o in s["offices"]:  # older settings stored one "ip" per office
        if "ips" not in o:
            o["ips"] = [o.pop("ip")] if o.get("ip") else []
    return s


def save_settings(s):
    atomic_write(SETTINGS, json.dumps(s, indent=2), 0o600)


def get_blocked():
    return load_json(BLOCKED, [])


def parse_nets(values):
    nets = []
    for v in values:
        try:
            nets.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            pass
    return nets


def allowed_networks(s=None):
    s = s or get_settings()
    return parse_nets([ip for o in s["offices"] for ip in o["ips"]] + s["extra_ips"])


def ip_allowed(ip, s=None):
    addr = ipaddress.ip_address(ip)
    return any(addr in n for n in allowed_networks(s))


def is_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


# ================================================================ certificates
def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def pem_cert(c):
    return c.public_bytes(serialization.Encoding.PEM)


def pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())


def san_for(host):
    return x509.IPAddress(ipaddress.ip_address(host)) if is_ip(host) else x509.DNSName(host)


def load_ca():
    c, k = read_bytes(f"{CA_DIR}/ca.pem"), read_bytes(f"{CA_DIR}/ca.key")
    cert = x509.load_pem_x509_certificate(c) if c else None
    key = serialization.load_pem_private_key(k, None) if k else None
    return cert, key


def create_ca(label):
    k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    n = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, label),
                   x509.NameAttribute(NameOID.COMMON_NAME, f"{label} RADIUS Root CA")])
    now = utcnow()
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
         .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .sign(k, hashes.SHA256()))
    atomic_write(f"{CA_DIR}/ca.key", pem_key(k), 0o600)
    atomic_write(f"{CA_DIR}/ca.pem", pem_cert(c))
    return c, k


def issue(ca_cert, ca_key, host, days):
    """Server certificate for `host`, signed by the CA (or self-signed when ca_cert is None)."""
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = utcnow()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    b = (x509.CertificateBuilder().subject_name(name)
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
         .add_extension(x509.SubjectAlternativeName([san_for(host)]), critical=False))
    if ca_cert is None:
        return b.issuer_name(name).sign(k, hashes.SHA256()), k
    b = (b.issuer_name(ca_cert.subject)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False))
    return b.sign(ca_key, hashes.SHA256()), k


def generate_server_cert(name, label):
    ca_cert, ca_key = load_ca()
    if ca_key is None:
        ca_cert, ca_key = create_ca(label)
    c, k = issue(ca_cert, ca_key, name, 1095)
    atomic_write(f"{CFG_DIR}/server.key", pem_key(k), 0o600)
    atomic_write(f"{CFG_DIR}/server-chain.pem", pem_cert(c) + pem_cert(ca_cert))


def generate_panel_cert(host):
    ca_cert, ca_key = load_ca()
    if ca_key is None:
        ca_cert = None
    c, k = issue(ca_cert, ca_key, host, 397)  # 397 days: the longest browsers accept
    atomic_write(f"{TLS_DIR}/panel.key", pem_key(k), 0o600)
    atomic_write(f"{TLS_DIR}/panel.pem", pem_cert(c) + (pem_cert(ca_cert) if ca_cert else b""))


# ---------------------------------------------------------------- device certificates
def device_ca(label):
    """The panel's own CA for laptop certificates. Trusted by RADIUS while it exists."""
    c, k = read_bytes(f"{DEVCA_DIR}/ca.pem"), read_bytes(f"{DEVCA_DIR}/ca.key")
    if c and k:
        return x509.load_pem_x509_certificate(c), serialization.load_pem_private_key(k, None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    n = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, label),
                   x509.NameAttribute(NameOID.COMMON_NAME, f"{label} Device CA")])
    now = utcnow()
    cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    atomic_write(f"{DEVCA_DIR}/ca.key", pem_key(key), 0o600)
    atomic_write(f"{DEVCA_DIR}/ca.pem", pem_cert(cert))
    atomic_write(f"{TRUST_DIR}/{fingerprint(cert)}.pem", pem_cert(cert))
    return cert, key


def issue_device_cert(device, label):
    """New key + 1-year client certificate for one laptop, as a Windows/macOS-compatible .pfx.
    The private key is never stored on the server."""
    ca_cert, ca_key = device_ca(label)
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = utcnow()
    c = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device)]))
         .issuer_name(ca_cert.subject).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=CERT_DAYS))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(device)]), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
         .sign(ca_key, hashes.SHA256()))
    password = secrets.token_urlsafe(18)
    # Legacy 3DES/SHA1 PKCS#12 so every Windows and macOS version can import it.
    enc = (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000)
           .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1())
           .build(password.encode()))
    pfx = pkcs12.serialize_key_and_certificates(device.encode(), k, c, [ca_cert], enc)
    return pfx, password, c


def get_devices():
    return load_json(DEVICES, [])


def save_devices(d):
    atomic_write(DEVICES, json.dumps(d, indent=2), 0o600)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def new_link(dev):
    token = secrets.token_urlsafe(24)
    dev.update(token=token_hash(token), token_expires=int(time.time()) + LINK_DAYS * 86400, token_used=False)
    return token


def build_installer(device, fmt):
    """Issue a fresh certificate and wrap it for the platform. Returns (bytes, filename, mimetype)."""
    s = get_settings()
    chain = server_chain()
    if len(chain) < 2:
        raise ValueError("The RADIUS server certificate is missing (Certificates page).")
    root_der = chain[-1].public_bytes(serialization.Encoding.DER)
    pfx, pw, cert = issue_device_cert(device, s["ssid"] or "Wi-Fi")
    devs = get_devices()
    for d in devs:
        if d["name"] == device:
            d.setdefault("certs", []).append({"serial": format(cert.serial_number, "x"), "issued": int(time.time()),
                                              "expires": int(cert.not_valid_after_utc.timestamp()), "format": fmt})
    save_devices(devs)
    if fmt == "windows":
        return (windows_installer(device, s["ssid"], s["server_name"], root_der, pfx, pw),
                f"Install-WiFi-{device}.cmd", "application/octet-stream")
    return (mac_profile(device, s["ssid"], s["server_name"], root_der, pfx, pw),
            f"WiFi-{device}.mobileconfig", "application/x-apple-aspen-config")


def parse_certs(data):
    """PEM (one or many) or DER bytes -> list of certificates."""
    try:
        if b"-----BEGIN" in data:
            return x509.load_pem_x509_certificates(data)
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        return []


def fingerprint(c):
    return c.fingerprint(hashes.SHA256()).hex()[:16]


def trusted_cas():
    out = []
    for f in sorted(os.listdir(TRUST_DIR)):
        if f.endswith(".pem"):
            for c in parse_certs(read_bytes(f"{TRUST_DIR}/{f}")):
                out.append((f[:-4], c))
    return out


def cert_info(c, fp=None):
    try:
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(v) for v in san.get_values_for_type(x509.DNSName)] + \
                [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    try:
        is_ca = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    exp = c.not_valid_after_utc
    return {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
            "san": ", ".join(names), "expires": exp.strftime("%Y-%m-%d"),
            "days_left": (exp - utcnow()).days, "is_ca": is_ca, "fp": fp or fingerprint(c)}


def server_chain():
    data = read_bytes(f"{CFG_DIR}/server-chain.pem")
    return parse_certs(data) if data else []


# ================================================================ apply to radius
def render_clients(s):
    out = ["# GENERATED by the RADIUS admin panel. Do not edit; use the Offices page.\n"]
    for o in s["offices"]:
        # One client block per public IP; all share the office's secret and name in the logs.
        for i, ip in enumerate(o["ips"]):
            block = o["name"] if i == 0 else f"{o['name']}__ip{i + 1}"
            out.append(
                f"client {block} {{\n\tipaddr = {ip}\n\tsecret = \"{o['secret']}\"\n"
                f"\tshortname = {o['name']}\n\trequire_message_authenticator = yes\n"
                f"\tlimit_proxy_state = yes\n}}\n")
    out.append(f"client localhost {{\n\tipaddr = 127.0.0.1\n\tsecret = \"{s['local_secret']}\"\n"
               f"\tshortname = localhost\n}}\n")
    return "\n".join(out)


def render_blocked(b):
    lines = ["# GENERATED by the RADIUS admin panel. Do not edit; use the Devices page."]
    lines += [f"{d['name']}\tAuth-Type := Reject" for d in b]
    return "\n".join(lines) + "\n"


def apply_config(reason):
    """Write every file radius reads, then ask the radius container to reload."""
    s = get_settings()
    atomic_write(f"{CFG_DIR}/clients.conf", render_clients(s))
    atomic_write(f"{CFG_DIR}/blocked-devices", render_blocked(get_blocked()))
    atomic_write(f"{CFG_DIR}/client-ca.pem", b"".join(pem_cert(c) for _, c in trusted_cas()))
    atomic_write(f"{CFG_DIR}/radiusd-args", "-xx\n" if s["debug"] else "\n")
    atomic_write(f"{CTL_DIR}/reload.request", f"{int(time.time())} {reason}\n")


def restart_panel_soon():
    """Exit so Docker restarts the panel with its new HTTPS certificate."""
    threading.Timer(2.0, lambda: os.kill(1, signal.SIGTERM)).start()


# ================================================================ logs + status
_cache = {}


def read_auth_log():
    rows = []
    for name in ("auth.log.1", "auth.log"):
        path = f"{LOG_DIR}/{name}"
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        key = (st.st_size, st.st_mtime)
        if _cache.get(path, (None,))[0] != key:
            parsed = []
            with open(path, errors="replace") as f:
                for line in f:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) < 10 or not parts[0].isdigit():
                        continue
                    parts += [""] * (len(FIELDS) - len(parts))
                    r = dict(zip(FIELDS, parts))
                    r["ts"] = int(r["ts"])
                    r["device"] = r["cn"] or r["user"].removeprefix("host/")
                    parsed.append(r)
            _cache[path] = (key, parsed)
        rows.extend(_cache[path][1])
    return rows[::-1]


def tail(path, n=200):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 256 * 1024))
            return f.read().decode(errors="replace").splitlines()[-n:]
    except FileNotFoundError:
        return []


def server_status():
    st = load_json(f"{CTL_DIR}/status.json", {})
    st["stale"] = not st or time.time() - st.get("updated", 0) > 15
    st["reload_error"] = (read_bytes(f"{CTL_DIR}/reload.error") or b"").decode(errors="replace").strip()
    st["reload_pending"] = os.path.exists(f"{CTL_DIR}/reload.request")
    return st


def checklist(s):
    cas = trusted_cas()
    status = server_status()
    public = [ip for o in s["offices"] for ip in o["ips"] if not ipaddress.ip_network(ip, strict=False).is_private]
    return [
        ("RADIUS server certificate", bool(server_chain()), "Certificates page: generate or import it."),
        ("Laptop certificates ready (add a laptop on the Devices page, or upload Intune CAs)",
         any("TEST" not in c.subject.rfc4514_string().upper() for _, c in cas),
         "Devices page: Add laptop. Or Certificates page: upload the Intune Cloud PKI CAs."),
        ("No TEST CA trusted", not any("TEST" in c.subject.rfc4514_string().upper() for _, c in cas),
         "Certificates page: remove the test CA before go-live."),
        ("At least one office with a public IP", bool(public), "Offices page."),
        ("RADIUS running", status.get("state") == "running" and not status["stale"],
         "See the error under the status bar."),
    ]


# ================================================================ app
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
_key_file = f"{P_DIR}/secret_key"
if not os.path.exists(_key_file):
    atomic_write(_key_file, secrets.token_hex(32), 0o600)
app.secret_key = open(_key_file).read().strip()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  SESSION_COOKIE_SECURE=True, SESSION_COOKIE_NAME="radius_panel")

with lock:
    if not get_settings()["configured"]:
        if not os.path.exists(SETUP_CODE):
            atomic_write(SETUP_CODE, f"{secrets.token_hex(3).upper()}-{secrets.token_hex(3).upper()}", 0o600)
        print("=" * 60 + f"\n  FIRST-RUN SETUP CODE: {open(SETUP_CODE).read()}\n"
              "  Open https://<server-ip>:8443 and enter this code.\n" + "=" * 60, flush=True)
    elif not os.path.exists(f"{CFG_DIR}/clients.conf"):
        apply_config("first start")


def intune_config():
    c = get_settings().get("intune") or {}
    return c if c.get("tenant_id") and c.get("client_id") and c.get("client_secret") else None


INTUNE = IntuneCache(f"{P_DIR}/intune-cache.json", intune_config)
INTUNE.start()


def client_ip():
    return request.remote_addr or "-"


@app.before_request
def guard():
    if request.endpoint == "static":
        return
    s = get_settings()
    if not s["configured"]:
        if request.endpoint != "setup":
            return redirect(url_for("setup"))
    elif not ip_allowed(client_ip(), s):
        abort(403)
    if request.method == "POST":
        tok = request.form.get("csrf") or request.headers.get("X-CSRF", "")
        if not hmac.compare_digest(tok, session.get("csrf", "x")):
            abort(400, "Form expired. Reload the page and try again.")


@app.after_request
def headers(resp):
    resp.headers.update({
        "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
        "Strict-Transport-Security": "max-age=31536000",
    })
    return resp


@app.context_processor
def inject():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    st = get_settings()
    return {"csrf": session["csrf"], "user": session.get("user"), "ssid": st["ssid"] or "Wi-Fi",
            "app_name": st["app_name"] or "WiFi RADIUS Authenticator",
            "intune": INTUNE.lookup, "intune_on": INTUNE.enabled()}


@app.template_filter("when")
def when(ts):
    return dt.datetime.fromtimestamp(int(ts), dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "-"


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user") or time.time() - session.get("seen", 0) > SESSION_IDLE:
            session.clear()
            return redirect(url_for("login", next=request.path))
        session["seen"] = time.time()
        return fn(*a, **kw)
    return wrapper


def throttled(ip):
    count, first = fails.get(ip, [0, 0])
    return count >= MAX_FAILS and time.time() - first < LOCK_SECS


def record_fail(ip):
    count, first = fails.get(ip, [0, 0])
    fails[ip] = [count + 1, first if count and time.time() - first < LOCK_SECS else time.time()]


def check_admin_password(s, user, password):
    a = s["admin"]
    ok_user = hmac.compare_digest(user, a["user"])
    ok_pass = bool(a["hash"]) and check_password_hash(a["hash"], password)
    return ok_user and ok_pass


def password_problem(pw, confirm):
    if len(pw) < 12:
        return "Password must be at least 12 characters."
    if pw != confirm:
        return "The two passwords don't match."
    return None


def split_ips(text):
    return [v for v in re.split(r"[\s,;]+", text.strip()) if v]


def validate_office(name, ips_text, secret, s, orig=""):
    """Returns (normalised IP list, errors, warning)."""
    errors, warn, ips = [], None, []
    if not NAME_RE.match(name) or name == "localhost" or "__" in name:
        errors.append("Office name: letters, digits, dash, single underscores (max 32), not 'localhost'.")
    raw = split_ips(ips_text)
    if not raw:
        errors.append("Enter at least one public IP.")
    if len(raw) > 32:
        errors.append("At most 32 IPs per office.")
    private = []
    for v in raw:
        try:
            net = ipaddress.ip_network(v, strict=True)
        except ValueError:
            errors.append(f"{v} is not a valid IP address (or range like 203.0.113.0/29).")
            continue
        if net.is_loopback or net.num_addresses > 256:
            errors.append(f"{v}: use a single IP or a range of /24 or smaller.")
            continue
        if net.is_private:
            private.append(v)
        norm = str(net.network_address) if net.num_addresses == 1 else str(net)
        if norm not in ips:
            ips.append(norm)
    for o in s["offices"]:
        if o["name"] != orig:
            clash = set(ips) & set(o["ips"])
            if clash:
                errors.append(f"{', '.join(sorted(clash))} already belongs to office {o['name']}.")
    if private:
        warn = (f"{', '.join(private)} is a private address. Aruba RADIUS reaches AWS from the office's PUBLIC IP "
                "(check with: curl -4 ifconfig.me).")
    if not SECRET_RE.match(secret):
        errors.append("Shared secret: 16-128 characters, no spaces, quotes, backslash, $ or braces.")
    if any(o["name"] == name and o["name"] != orig for o in s["offices"]):
        errors.append(f"An office called {name} already exists.")
    return ips, errors, warn


def guard_lockout(new_settings):
    """Refuse a change that would lock the current admin out of the panel."""
    if not ip_allowed(client_ip(), new_settings):
        flash(f"Not saved: your current IP {client_ip()} would no longer be allowed to open this panel. "
              "Add it as an office or an extra admin IP first.", "error")
        return False
    return True


# ---------------------------------------------------------------- setup + login
@app.route("/setup", methods=["GET", "POST"])
def setup():
    s = get_settings()
    if s["configured"]:
        abort(404)
    form = {"ssid": "", "user": "admin", "office": "office_1", "ip": client_ip(),
            "server_name": s["server_name"], "panel_host": request.host.rsplit(":", 1)[0].strip("[]")}
    if request.method == "POST":
        form.update({k: request.form.get(k, "").strip() for k in form})
        code = (read_bytes(SETUP_CODE) or b"").decode().strip()
        errors = []
        if throttled(client_ip()):
            errors.append("Too many wrong setup codes. Try again in 15 minutes.")
        elif not code or not hmac.compare_digest(request.form.get("code", "").strip().upper(), code):
            record_fail(client_ip())
            errors.append("Wrong setup code. Find it with: sudo docker compose logs panel")
        if not SSID_RE.match(form["ssid"]):
            errors.append("SSID: 1-32 letters, digits, space, dot, dash or underscore.")
        if not NAME_RE.match(form["user"]):
            errors.append("Admin username: letters, digits, dash, underscore.")
        p = password_problem(request.form.get("password", ""), request.form.get("confirm", ""))
        if p:
            errors.append(p)
        if not HOST_RE.match(form["server_name"]):
            errors.append("RADIUS server name must look like radius.example.internal.")
        if not (HOST_RE.match(form["panel_host"]) or is_ip(form["panel_host"])):
            errors.append("Panel address must be the server's public IP or DNS name.")
        secret = gen_secret()
        ips, oerr, warn = validate_office(form["office"], form["ip"], secret, s)
        errors += oerr
        if not errors:
            new = dict(s)
            new.update(ssid=form["ssid"], server_name=form["server_name"], panel_host=form["panel_host"],
                       admin={"user": form["user"], "hash": generate_password_hash(request.form["password"])},
                       offices=[{"name": form["office"], "ips": ips, "secret": secret}], configured=True)
            if not ip_allowed(client_ip(), new):
                new["extra_ips"] = [client_ip()]
            with lock:
                generate_server_cert(new["server_name"], new["ssid"])
                generate_panel_cert(new["panel_host"])
                save_settings(new)
                apply_config("setup")
                os.remove(SETUP_CODE)
            session.clear()
            session.update(user=form["user"], seen=time.time(), csrf=secrets.token_urlsafe(24))
            audit("setup", f"ssid={new['ssid']} office={form['office']} ips={' '.join(ips)}")
            if warn:
                flash(warn, "info")
            restart_panel_soon()
            return render_template("restarting.html", host=new["panel_host"], first=True)
        for e in errors:
            flash(e, "error")
    return render_template("setup.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = client_ip()
    if request.method == "POST":
        if throttled(ip):
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return render_template("login.html"), 429
        s = get_settings()
        if check_admin_password(s, request.form.get("username", ""), request.form.get("password", "")):
            fails.pop(ip, None)
            session.clear()
            session.update(user=s["admin"]["user"], seen=time.time(), csrf=secrets.token_urlsafe(24))
            audit("login")
            nxt = request.args.get("next", "/")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")
        record_fail(ip)
        with open(AUDIT, "a") as f:
            f.write(f"{int(time.time())}\t-\t{ip}\tlogin failed\t{request.form.get('username', '')[:32]}\n")
        time.sleep(1)
        flash("Wrong username or password.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    if session.get("user"):
        audit("logout")
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- dashboard + logs
@app.route("/")
@login_required
def dashboard():
    s = get_settings()
    rows = read_auth_log()
    recent = [r for r in rows if r["ts"] >= time.time() - 86400]
    per_office = {}
    for r in recent:
        o = per_office.setdefault(r["office"] or "?", {"ACCEPT": 0, "REJECT": 0})
        o[r["result"]] = o.get(r["result"], 0) + 1
    certs = [cert_info(c) for c in server_chain()] + [cert_info(c) for _, c in trusted_cas()]
    ok_devices = {r["device"] for r in recent if r["result"] == "ACCEPT" and r["device"]}
    not_in_intune = sorted(d for d in ok_devices if INTUNE.enabled() and not INTUNE.lookup(d))
    noncompliant = sorted(d for d in ok_devices if (INTUNE.lookup(d) or {}).get("complianceState") == "noncompliant")
    return render_template(
        "dashboard.html", status=server_status(), events=rows[:15], checks=checklist(s),
        not_in_intune=not_in_intune, noncompliant=noncompliant, intune_state=INTUNE.state(),
        accepts=sum(r["result"] == "ACCEPT" for r in recent),
        rejects=sum(r["result"] == "REJECT" for r in recent),
        devices=len({r["device"] for r in recent if r["result"] == "ACCEPT"}),
        per_office=per_office, expiring=[c for c in certs if c["days_left"] < 60],
        blocked=len(get_blocked()))


def filtered_rows():
    rows = read_auth_log()
    q = request.args.get("q", "").strip().lower()
    res, office = request.args.get("result", ""), request.args.get("office", "")
    hours = request.args.get("hours", "168")
    if hours.isdigit() and int(hours):
        cutoff = time.time() - int(hours) * 3600
        rows = [r for r in rows if r["ts"] >= cutoff]
    if res in ("ACCEPT", "REJECT"):
        rows = [r for r in rows if r["result"] == res]
    if office:
        rows = [r for r in rows if r["office"] == office]
    if q:
        rows = [r for r in rows if any(q in str(r[k]).lower()
                                       for k in ("device", "mac", "src", "nas", "ap", "reason", "user"))]
    return rows


@app.route("/logins")
@login_required
def logins():
    rows = filtered_rows()
    offices = sorted({o["name"] for o in get_settings()["offices"]} | {"localhost"})
    return render_template("logins.html", rows=rows[:1000], total=len(rows), offices=offices, args=request.args)


@app.route("/logins.csv")
@login_required
def logins_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time_utc", "result", "device", "mac", "office", "source_ip", "nas_id", "ssid", "ap", "reason",
                "intune_user", "intune_model", "intune_serial", "intune_os", "intune_compliance"])
    for r in filtered_rows():
        i = INTUNE.lookup(r["device"]) or {}
        w.writerow([when(r["ts"]), r["result"], r["device"], r["mac"], r["office"], r["src"],
                    r["nas"], r["ssid"], r["ap"], r["reason"], i.get("userPrincipalName", ""),
                    f"{i.get('manufacturer', '')} {i.get('model', '')}".strip(), i.get("serialNumber", ""),
                    f"{i.get('operatingSystem', '')} {i.get('osVersion', '')}".strip(), i.get("complianceState", "")])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=wifi-logins.csv"})


# ---------------------------------------------------------------- devices
@app.route("/devices")
@login_required
def devices():
    seen = {}
    for r in read_auth_log():
        d = seen.get(r["device"])
        if d is None:
            d = seen[r["device"]] = {"name": r["device"], "last": r["ts"], "result": r["result"], "mac": r["mac"],
                                     "office": r["office"], "reason": r["reason"], "ok": 0, "bad": 0}
        d["ok" if r["result"] == "ACCEPT" else "bad"] += 1
    blocked = get_blocked()
    return render_template("devices.html", seen=[d for k, d in seen.items() if k], blocked=blocked,
                           bnames={b["name"].lower() for b in blocked}, laptops=get_devices(), now=time.time())


@app.post("/devices/block")
@login_required
def block_device():
    name = request.form.get("name", "").strip()
    note = request.form.get("note", "").strip()[:200].replace("\t", " ").replace("\n", " ")
    if not DEVICE_RE.match(name):
        flash("Device name may contain only letters, digits, dot, dash and underscore.", "error")
        return redirect(url_for("devices"))
    with lock:
        b = get_blocked()
        if name.lower() in {x["name"].lower() for x in b}:
            flash(f"{name} is already blocked.", "info")
            return redirect(url_for("devices"))
        b.append({"name": name, "note": note, "by": session["user"], "at": int(time.time())})
        atomic_write(BLOCKED, json.dumps(b, indent=2))
        apply_config(f"block {name}")
    audit("block device", f"{name} {note}")
    flash(f"{name} blocked. It takes effect within a few seconds. Also retire or wipe the laptop in Intune.", "ok")
    return redirect(url_for("devices"))


@app.post("/devices/unblock")
@login_required
def unblock_device():
    name = request.form.get("name", "")
    with lock:
        atomic_write(BLOCKED, json.dumps([x for x in get_blocked() if x["name"] != name], indent=2))
        apply_config(f"unblock {name}")
    audit("unblock device", name)
    flash(f"{name} unblocked.", "ok")
    return redirect(url_for("devices"))


# ---------------------------------------------------------------- offices
@app.route("/offices")
@login_required
def offices():
    return render_template("offices.html", settings=get_settings(), suggested=gen_secret(), my_ip=client_ip())


@app.post("/offices/save")
@login_required
def save_office():
    orig = request.form.get("orig", "")
    name, ip = request.form.get("name", "").strip(), request.form.get("ip", "").strip()
    secret = request.form.get("secret", "").strip()
    with lock:
        s = get_settings()
        current = next((o for o in s["offices"] if o["name"] == orig), None)
        if not secret and current:
            secret = current["secret"]
        ips, errors, warn = validate_office(name, ip, secret, s, orig)
        if errors:
            for e in errors:
                flash(e, "error")
            return redirect(url_for("offices"))
        new = json.loads(json.dumps(s))
        entry = {"name": name, "ips": ips, "secret": secret}
        if current:
            new["offices"][s["offices"].index(current)] = entry
        else:
            new["offices"].append(entry)
        if not guard_lockout(new):
            return redirect(url_for("offices"))
        save_settings(new)
        apply_config(f"office {name}")
    changed = "secret changed" if not current or current["secret"] != secret else "secret unchanged"
    audit("save office", f"{name} ips={' '.join(ips)} {changed}")
    if warn:
        flash(warn, "info")
    flash(f"Office {name} saved ({len(ips)} IP{'s' if len(ips) != 1 else ''}). If the IPs changed, update the AWS Security Group too. "
          "If the secret changed, re-apply that office's Aruba config.", "ok")
    return redirect(url_for("offices"))


@app.post("/offices/delete")
@login_required
def delete_office():
    name = request.form.get("name", "")
    with lock:
        new = get_settings()
        new["offices"] = [o for o in new["offices"] if o["name"] != name]
        if not guard_lockout(new):
            return redirect(url_for("offices"))
        save_settings(new)
        apply_config(f"delete office {name}")
    audit("delete office", name)
    flash(f"Office {name} removed. Its access points can no longer authenticate.", "ok")
    return redirect(url_for("offices"))


@app.route("/offices/<name>/aruba")
@login_required
def aruba_config(name):
    s = get_settings()
    o = next((o for o in s["offices"] if o["name"] == name), None)
    if not o:
        abort(404)
    audit("view aruba config", name)
    return render_template("aruba.html", o=o, s=s)


# ---------------------------------------------------------------- certificates
@app.route("/certificates")
@login_required
def certificates():
    _, ca_key = load_ca()
    chain = server_chain()
    panel = parse_certs(read_bytes(f"{TLS_DIR}/panel.pem") or b"")
    return render_template(
        "certificates.html", s=get_settings(), server=cert_info(chain[0]) if chain else None,
        root=cert_info(chain[-1]) if len(chain) > 1 else None,
        trusted=[cert_info(c, fp) for fp, c in trusted_cas()],
        panel=cert_info(panel[0]) if panel else None, has_ca_key=ca_key is not None)


@app.post("/certificates/trusted/upload")
@login_required
def upload_trusted():
    added = []
    for f in request.files.getlist("files"):
        certs = parse_certs(f.read())
        if not certs:
            flash(f"{f.filename}: not a certificate (.cer, .crt or .pem).", "error")
            continue
        for c in certs:
            info = cert_info(c)
            if not info["is_ca"]:
                flash(f"{f.filename}: {info['subject']} is not a CA certificate; skipped.", "error")
                continue
            atomic_write(f"{TRUST_DIR}/{info['fp']}.pem", pem_cert(c))
            added.append(info["subject"])
    if added:
        with lock:
            apply_config("trusted CA upload")
        audit("upload laptop CA", "; ".join(added))
        flash(f"Trusted: {'; '.join(added)}. RADIUS is reloading.", "ok")
    return redirect(url_for("certificates"))


@app.post("/certificates/trusted/remove")
@login_required
def remove_trusted():
    fp = request.form.get("fp", "")
    if re.fullmatch(r"[0-9a-f]{16}", fp) and os.path.exists(f"{TRUST_DIR}/{fp}.pem"):
        os.remove(f"{TRUST_DIR}/{fp}.pem")
        with lock:
            apply_config("trusted CA removed")
        audit("remove laptop CA", fp)
        flash("CA removed. Laptops with certificates from it can no longer connect.", "ok")
    return redirect(url_for("certificates"))


@app.post("/certificates/server/generate")
@login_required
def regen_server():
    name = request.form.get("server_name", "").strip()
    if not HOST_RE.match(name):
        flash("Server name must look like radius.example.internal.", "error")
        return redirect(url_for("certificates"))
    with lock:
        s = get_settings()
        s["server_name"] = name
        generate_server_cert(name, s["ssid"] or "Wi-Fi")
        save_settings(s)
        apply_config("server certificate")
    audit("generate server certificate", name)
    flash(f"New RADIUS server certificate for {name}. The Intune Wi-Fi profile's server name must be {name}. "
          "The root CA is unchanged, so Intune needs no new trusted certificate.", "ok")
    return redirect(url_for("certificates"))


@app.post("/certificates/server/import")
@login_required
def import_server():
    def upload(field):
        f = request.files.get(field)
        return f.read() if f and f.filename else b""

    certs, cas = parse_certs(upload("cert")), parse_certs(upload("ca"))
    try:
        key = serialization.load_pem_private_key(upload("key"), None)
    except (ValueError, TypeError):
        key = None
    ca_key, ca_key_data = None, upload("ca_key")
    err = None
    if ca_key_data:
        try:
            ca_key = serialization.load_pem_private_key(ca_key_data, None)
        except (ValueError, TypeError):
            err = "The CA private key could not be read (it must be an unencrypted PEM)."
    if err:
        pass
    elif not certs or not cas or key is None:
        err = "Upload the server certificate, its private key (unencrypted PEM) and the root CA."
    elif certs[0].public_key().public_numbers() != key.public_key().public_numbers():
        err = "The private key does not belong to the server certificate."
    elif certs[0].issuer != cas[0].subject:
        err = "The server certificate was not issued by that root CA."
    elif ca_key and ca_key.public_key().public_numbers() != cas[0].public_key().public_numbers():
        err = "The CA private key does not belong to the root CA."
    if err:
        flash(err, "error")
        return redirect(url_for("certificates"))
    with lock:
        atomic_write(f"{CFG_DIR}/server.key", pem_key(key), 0o600)
        atomic_write(f"{CFG_DIR}/server-chain.pem", pem_cert(certs[0]) + pem_cert(cas[0]))
        atomic_write(f"{CA_DIR}/ca.pem", pem_cert(cas[0]))
        if ca_key:
            atomic_write(f"{CA_DIR}/ca.key", pem_key(ca_key), 0o600)
        elif os.path.exists(f"{CA_DIR}/ca.key"):
            os.remove(f"{CA_DIR}/ca.key")
        s = get_settings()
        cn = certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        s["server_name"] = cn[0].value if cn else s["server_name"]
        save_settings(s)
        apply_config("server certificate import")
    audit("import server certificate", certs[0].subject.rfc4514_string())
    flash("Server certificate imported. RADIUS is reloading.", "ok")
    return redirect(url_for("certificates"))


# ---------------------------------------------------------------- laptop enrollment
def _download(data_name_mime):
    data, name, mime = data_name_mime
    return Response(data, mimetype=mime, headers={"Content-Disposition": f"attachment; filename={name}"})


@app.post("/devices/add")
@login_required
def add_device():
    name = request.form.get("name", "").strip()
    note = request.form.get("note", "").strip()[:100].replace("\t", " ").replace("\n", " ")
    if not DEVICE_RE.match(name):
        flash("Laptop name: letters, digits, dot, dash, underscore (e.g. LT-042 or anna-macbook).", "error")
        return redirect(url_for("devices"))
    with lock:
        devs = get_devices()
        if any(d["name"].lower() == name.lower() for d in devs):
            flash(f"{name} already exists. Use 'New install link' on it instead.", "error")
            return redirect(url_for("devices"))
        dev = {"name": name, "note": note, "created": int(time.time()), "by": session["user"], "certs": []}
        token = new_link(dev)
        devs.append(dev)
        save_devices(devs)
    audit("add laptop", f"{name} {note}")
    return render_template("enroll_link.html", dev=dev, link=enroll_url(token))


def enroll_url(token):
    host = get_settings()["panel_host"] or request.host.rsplit(":", 1)[0]
    return f"https://{host}:8443/enroll/{token}"


@app.post("/devices/<name>/link")
@login_required
def device_link(name):
    with lock:
        devs = get_devices()
        dev = next((d for d in devs if d["name"] == name), None)
        if not dev:
            abort(404)
        token = new_link(dev)
        save_devices(devs)
    audit("new install link", name)
    return render_template("enroll_link.html", dev=dev, link=enroll_url(token))


@app.post("/devices/<name>/download")
@login_required
def device_download(name):
    fmt = request.form.get("format")
    if fmt not in ("windows", "mac") or not any(d["name"] == name for d in get_devices()):
        abort(400)
    try:
        with lock:
            out = build_installer(name, fmt)
            apply_config("device certificate")
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("devices"))
    audit("download installer", f"{name} ({fmt})")
    return _download(out)


@app.post("/devices/<name>/remove")
@login_required
def device_remove(name):
    with lock:
        save_devices([d for d in get_devices() if d["name"] != name])
        b = get_blocked()
        if name.lower() not in {x["name"].lower() for x in b}:
            b.append({"name": name, "note": "laptop removed", "by": session["user"], "at": int(time.time())})
            atomic_write(BLOCKED, json.dumps(b, indent=2))
        apply_config(f"remove laptop {name}")
    audit("remove laptop", name)
    flash(f"{name} removed and blocked. Its certificate no longer connects.", "ok")
    return redirect(url_for("devices"))


def find_token(token):
    h = token_hash(token)
    for d in get_devices():
        if d.get("token") and hmac.compare_digest(d["token"], h):
            if d.get("token_used") or time.time() > d.get("token_expires", 0):
                return d, "This install link was already used or has expired. Ask IT for a new one."
            return d, None
    return None, "This install link is not valid. Ask IT for a new one."


@app.route("/enroll/<token>", methods=["GET", "POST"])
def enroll(token):
    if throttled(client_ip()):
        abort(429)
    dev, problem = find_token(token)
    if not dev:
        record_fail(client_ip())
    if problem or request.method == "GET":
        return render_template("enroll.html", dev=dev, problem=problem, token=token)
    fmt = request.form.get("format")
    if fmt not in ("windows", "mac"):
        abort(400)
    try:
        with lock:
            dev, problem = find_token(token)  # re-check under the lock: one download per link
            if problem:
                return render_template("enroll.html", dev=dev, problem=problem, token=token)
            out = build_installer(dev["name"], fmt)
            devs = get_devices()
            for d in devs:
                if d["name"] == dev["name"]:
                    d["token_used"] = True
            save_devices(devs)
            apply_config("device certificate")
    except ValueError as e:
        return render_template("enroll.html", dev=dev, problem=str(e), token=token)
    with open(AUDIT, "a") as f:
        f.write(f"{int(time.time())}\t(install link)\t{client_ip()}\tlaptop installed\t{dev['name']} ({fmt})\n")
    return _download(out)


@app.route("/certificates/root-ca.cer")
@login_required
def download_root():
    chain = server_chain()
    if len(chain) < 2:
        abort(404)
    return Response(chain[-1].public_bytes(serialization.Encoding.DER), mimetype="application/pkix-cert",
                    headers={"Content-Disposition": "attachment; filename=RADIUS-Root-CA.cer"})


@app.post("/certificates/panel/generate")
@login_required
def regen_panel():
    host = request.form.get("panel_host", "").strip()
    if not (HOST_RE.match(host) or is_ip(host)):
        flash("Panel address must be the server's public IP or DNS name.", "error")
        return redirect(url_for("certificates"))
    with lock:
        s = get_settings()
        s["panel_host"] = host
        generate_panel_cert(host)
        save_settings(s)
    audit("generate panel certificate", host)
    restart_panel_soon()
    return render_template("restarting.html", host=host, first=False)


# ---------------------------------------------------------------- settings
@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html", s=get_settings(), my_ip=client_ip(), istate=INTUNE.state())


@app.post("/settings/general")
@login_required
def save_general():
    ssid = request.form.get("ssid", "").strip()
    app_name = " ".join(request.form.get("app_name", "").split())[:40] or "WiFi RADIUS Authenticator"
    extra = request.form.get("extra_ips", "").replace(",", " ").split()
    debug = request.form.get("debug") == "on"
    errors = []
    if not SSID_RE.match(ssid):
        errors.append("SSID: 1-32 letters, digits, space, dot, dash or underscore.")
    for e in extra:
        try:
            if ipaddress.ip_network(e, strict=False).num_addresses > 256:
                errors.append(f"{e}: use a single IP or a range of /24 or smaller.")
        except ValueError:
            errors.append(f"{e} is not a valid IP address.")
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("settings_page"))
    with lock:
        new = get_settings()
        new.update(ssid=ssid, extra_ips=extra, debug=debug, app_name=app_name)
        if not guard_lockout(new):
            return redirect(url_for("settings_page"))
        save_settings(new)
        apply_config("settings")
    audit("save settings", f"name={app_name} ssid={ssid} extra_ips={' '.join(extra)} debug={debug}")
    flash("Settings saved.", "ok")
    return redirect(url_for("settings_page"))


@app.post("/settings/intune")
@login_required
def save_intune():
    if request.form.get("action") == "disconnect":
        with lock:
            s = get_settings()
            s["intune"] = {}
            save_settings(s)
        audit("intune disconnected")
        flash("Intune connection removed.", "ok")
        return redirect(url_for("settings_page"))
    tenant = request.form.get("tenant_id", "").strip()
    client = request.form.get("client_id", "").strip()
    secret = request.form.get("client_secret", "").strip()
    current = get_settings().get("intune") or {}
    secret = secret or current.get("client_secret", "")
    errors = []
    if not (GUID_RE.match(tenant) or HOST_RE.match(tenant)):
        errors.append("Tenant ID: the Directory (tenant) ID from the app registration's Overview page.")
    if not GUID_RE.match(client):
        errors.append("Client ID: the Application (client) ID from the app registration's Overview page.")
    if not secret or len(secret) > 256 or any(ch in secret for ch in "\r\n"):
        errors.append("Client secret: paste the secret's Value (not its ID).")
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("settings_page"))
    with lock:
        s = get_settings()
        s["intune"] = {"tenant_id": tenant, "client_id": client, "client_secret": secret}
        save_settings(s)
    ok = INTUNE.refresh()
    st = INTUNE.state()
    audit("intune connected" if ok else "intune connection failed", tenant)
    if ok:
        flash(f"Connected to Intune: {st['count']} devices found. Details now show on Logins and Devices.", "ok")
    else:
        flash(f"Saved, but Intune said: {st['error']}", "error")
    return redirect(url_for("settings_page"))


@app.post("/settings/intune/refresh")
@login_required
def refresh_intune():
    ok = INTUNE.refresh()
    st = INTUNE.state()
    flash(f"Intune refreshed: {st['count']} devices." if ok else f"Intune said: {st['error']}", "ok" if ok else "error")
    return redirect(request.referrer or url_for("settings_page"))


@app.post("/settings/admin")
@login_required
def save_admin():
    s = get_settings()
    if not check_admin_password(s, s["admin"]["user"], request.form.get("current", "")):
        flash("Current password is wrong.", "error")
        return redirect(url_for("settings_page"))
    user, pw = request.form.get("user", "").strip(), request.form.get("password", "")
    if not NAME_RE.match(user):
        flash("Username: letters, digits, dash, underscore.", "error")
        return redirect(url_for("settings_page"))
    if pw:
        p = password_problem(pw, request.form.get("confirm", ""))
        if p:
            flash(p, "error")
            return redirect(url_for("settings_page"))
    with lock:
        s = get_settings()
        s["admin"]["user"] = user
        if pw:
            s["admin"]["hash"] = generate_password_hash(pw)
        save_settings(s)
    session["user"] = user
    audit("change admin account", f"user={user} password {'changed' if pw else 'unchanged'}")
    flash("Admin account updated.", "ok")
    return redirect(url_for("settings_page"))


# ---------------------------------------------------------------- configuration view
@app.route("/config")
@login_required
def config():
    masked = re.sub(r'secret = "[^"]*"', 'secret = "********"', render_clients(get_settings()))
    return render_template(
        "config.html", clients=masked, blocked_file=render_blocked(get_blocked()), status=server_status(),
        radius_log=tail(f"{LOG_DIR}/radius.log", 300),
        audit_log=[l.split("\t") for l in reversed(tail(AUDIT, 200))])


@app.post("/reload")
@login_required
def reload_radius():
    with lock:
        apply_config("manual reload")
    audit("reload")
    flash("Reload requested.", "ok")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/api/status")
@login_required
def api_status():
    return jsonify(server_status())


@app.errorhandler(403)
def forbidden(_):
    return "Forbidden", 403


@app.errorhandler(413)
def too_big(_):
    flash("File too large (max 256 KB).", "error")
    return redirect(url_for("certificates"))
