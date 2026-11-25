"""Minimal SCEP server (RFC 8894) so an MDM such as Jamf Pro can give every Mac its own
Wi-Fi certificate automatically. The Mac generates its key; only its CSR reaches us.

Operations: GetCACaps, GetCACert (RA + CA), PKIOperation (PKCSReq with a challenge
password, RenewalReq signed with a certificate we issued earlier).
"""
import datetime as dt
import hashlib
import hmac
import os

from asn1crypto import cms, core
from asn1crypto import x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import AttributeOID, NameOID

CAPS = "POSTPKIOperation\nSHA-256\nSHA-1\nAES\nDES3\nRenewal\nSCEPStandard\n"


# ---------------------------------------------------------------- SCEP attributes in asn1crypto
class _SetOfPrintable(core.SetOf):
    _child_spec = core.PrintableString


class _SetOfOctets(core.SetOf):
    _child_spec = core.OctetString


_ATTRS = {
    "2.16.840.1.113733.1.9.2": ("scep_message_type", _SetOfPrintable),
    "2.16.840.1.113733.1.9.3": ("scep_pki_status", _SetOfPrintable),
    "2.16.840.1.113733.1.9.4": ("scep_fail_info", _SetOfPrintable),
    "2.16.840.1.113733.1.9.5": ("scep_sender_nonce", _SetOfOctets),
    "2.16.840.1.113733.1.9.6": ("scep_recipient_nonce", _SetOfOctets),
    "2.16.840.1.113733.1.9.7": ("scep_transaction_id", _SetOfPrintable),
}
for _oid, (_name, _spec) in _ATTRS.items():
    cms.CMSAttributeType._map[_oid] = _name
    cms.CMSAttribute._oid_specs[_name] = _spec
cms.CMSAttributeType._reverse_map = None

PKCS_REQ, RENEWAL_REQ, CERT_REP = "19", "17", "3"
SUCCESS, FAILURE = "0", "2"
BAD_ALG, BAD_MESSAGE_CHECK, BAD_REQUEST = "0", "1", "2"


class ScepError(Exception):
    def __init__(self, msg, fail_info=BAD_REQUEST):
        super().__init__(msg)
        self.fail_info = fail_info


# ---------------------------------------------------------------- helpers
def _a(cert):
    """cryptography certificate -> asn1crypto certificate."""
    return ax509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def _hash(name):
    return {"sha1": hashes.SHA1(), "sha256": hashes.SHA256(), "sha512": hashes.SHA512(),
            "sha384": hashes.SHA384(), "sha224": hashes.SHA224()}[name]


def degenerate(certs):
    """certs-only SignedData (used for GetCACert and inside CertRep)."""
    sd = cms.SignedData({"version": "v1", "digest_algorithms": [], "encap_content_info": {"content_type": "data"},
                         "certificates": [_a(c) for c in certs], "signer_infos": []})
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()


def _cipher(name, key, iv):
    if name.startswith("aes"):
        return Cipher(algorithms.AES(key), modes.CBC(iv)), 128
    if name in ("tripledes_3key", "des3"):
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        return Cipher(TripleDES(key), modes.CBC(iv)), 64
    raise ScepError(f"unsupported content encryption {name}", BAD_ALG)


def _decrypt_envelope(env_der, keys):
    env = cms.ContentInfo.load(env_der)["content"]
    eci = env["encrypted_content_info"]
    alg = eci["content_encryption_algorithm"]
    name = alg["algorithm"].native
    iv = alg["parameters"].native
    ct = eci["encrypted_content"].native
    for ri in env["recipient_infos"]:
        if ri.name != "ktri":
            continue
        for key in keys:
            try:
                cek = key.decrypt(ri.chosen["encrypted_key"].native, padding.PKCS1v15())
            except ValueError:
                continue
            cipher, block = _cipher(name, cek, iv)
            d = cipher.decryptor()
            u = sympad.PKCS7(block).unpadder()
            return u.update(d.update(ct) + d.finalize()) + u.finalize(), name
    raise ScepError("cannot decrypt request (wrong recipient certificate)", BAD_MESSAGE_CHECK)


def _encrypt_envelope(plain, recipient_a, alg_name):
    if alg_name.startswith("aes"):
        name, key, iv, block = "aes256_cbc", os.urandom(32), os.urandom(16), 128
    else:
        name, key, iv, block = "tripledes_3key", os.urandom(24), os.urandom(8), 64
    cipher, _ = _cipher(name, key, iv)
    p = sympad.PKCS7(block).padder()
    e = cipher.encryptor()
    ct = e.update(p.update(plain) + p.finalize()) + e.finalize()
    pub = x509.load_der_x509_certificate(recipient_a.dump()).public_key()
    tbs = recipient_a["tbs_certificate"]
    env = cms.EnvelopedData({
        "version": "v0",
        "recipient_infos": [cms.RecipientInfo(name="ktri", value=cms.KeyTransRecipientInfo({
            "version": "v0",
            "rid": cms.RecipientIdentifier(name="issuer_and_serial_number", value=cms.IssuerAndSerialNumber(
                {"issuer": tbs["issuer"], "serial_number": tbs["serial_number"].native})),
            "key_encryption_algorithm": {"algorithm": "rsaes_pkcs1v15"},
            "encrypted_key": pub.encrypt(key, padding.PKCS1v15())}))],
        "encrypted_content_info": {"content_type": "data",
                                   "content_encryption_algorithm": {"algorithm": name, "parameters": iv},
                                   "encrypted_content": ct}})
    return cms.ContentInfo({"content_type": "enveloped_data", "content": env}).dump()


def _cert_rep(ra_cert, ra_key, txid, req_nonce, status, content=None, fail_info=None):
    """Signed CertRep message."""
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    econtent = content or b""
    attrs = [
        {"type": "content_type", "values": ["data"]},
        {"type": "signing_time", "values": [cms.Time(name="utc_time", value=now)]},
        {"type": "message_digest", "values": [hashlib.sha256(econtent).digest()]},
        {"type": "scep_message_type", "values": [CERT_REP]},
        {"type": "scep_pki_status", "values": [status]},
        {"type": "scep_transaction_id", "values": [txid]},
        {"type": "scep_sender_nonce", "values": [os.urandom(16)]},
        {"type": "scep_recipient_nonce", "values": [req_nonce]},
    ]
    if fail_info is not None:
        attrs.append({"type": "scep_fail_info", "values": [fail_info]})
    # DER requires SET OF members sorted by their encoding; verifiers re-encode before checking.
    signed_attrs = cms.CMSAttributes(sorted((cms.CMSAttribute(a) for a in attrs), key=lambda a: a.dump()))
    sig = ra_key.sign(signed_attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
    ra_a = _a(ra_cert)
    si = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier(name="issuer_and_serial_number", value=cms.IssuerAndSerialNumber(
            {"issuer": ra_a["tbs_certificate"]["issuer"], "serial_number": ra_a["tbs_certificate"]["serial_number"].native})),
        "digest_algorithm": {"algorithm": "sha256"},
        "signed_attrs": signed_attrs,
        "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
        "signature": sig})
    encap = {"content_type": "data"}
    if content is not None:
        encap["content"] = content
    sd = cms.SignedData({"version": "v1", "digest_algorithms": [{"algorithm": "sha256"}],
                         "encap_content_info": encap, "certificates": [ra_a], "signer_infos": [si]})
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()


# ---------------------------------------------------------------- main entry
def pki_operation(der, ra_cert, ra_key, ca_cert, ca_key, check_request, issue):
    """Handle one PKIOperation.

    check_request(message_type, csr, challenge, signer_cert) -> None or raises ScepError
    issue(csr) -> issued cryptography certificate
    Returns (response_der, info dict for logging).
    """
    try:
        sd = cms.ContentInfo.load(der)["content"]
        si = sd["signer_infos"][0]
        attrs = {a["type"].native: a["values"][0].native for a in si["signed_attrs"]}
        txid, nonce = attrs.get("scep_transaction_id"), attrs.get("scep_sender_nonce")
        mtype = attrs.get("scep_message_type")
        if not txid or nonce is None or mtype is None:
            raise ValueError("missing SCEP attributes")
    except Exception as e:  # unparseable: nothing to sign a reply with
        raise ValueError(f"not a SCEP message: {e}") from None
    info = {"transaction": txid, "type": mtype}
    try:
        econtent = sd["encap_content_info"]["content"].native
        # Signer: the requester's self-signed (PKCSReq) or previously issued (RenewalReq) certificate.
        sid = si["sid"].chosen
        signer_a = next((c.chosen for c in sd["certificates"]
                         if c.name == "certificate"
                         and c.chosen["tbs_certificate"]["serial_number"].native == sid["serial_number"].native),
                        None)
        if signer_a is None:
            raise ScepError("signer certificate missing", BAD_MESSAGE_CHECK)
        signer = x509.load_der_x509_certificate(signer_a.dump())
        dname = si["digest_algorithm"]["algorithm"].native
        if not hmac.compare_digest(hashlib.new(dname, econtent).digest(), attrs.get("message_digest", b"")):
            raise ScepError("message digest mismatch", BAD_MESSAGE_CHECK)
        to_verify = b"\x31" + si["signed_attrs"].dump()[1:]
        signer.public_key().verify(si["signature"].native, to_verify, padding.PKCS1v15(), _hash(dname))
        plain, enc_alg = _decrypt_envelope(econtent, [ra_key, ca_key])
        csr = x509.load_der_x509_csr(plain)
        if not csr.is_signature_valid:
            raise ScepError("CSR signature invalid", BAD_MESSAGE_CHECK)
        try:
            challenge = csr.attributes.get_attribute_for_oid(AttributeOID.CHALLENGE_PASSWORD).value
            challenge = challenge.decode() if isinstance(challenge, bytes) else str(challenge)
        except x509.AttributeNotFound:
            challenge = ""
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        info["cn"] = cn[0].value if cn else ""
        if mtype not in (PKCS_REQ, RENEWAL_REQ):
            raise ScepError(f"unsupported message type {mtype}")
        check_request(mtype, csr, challenge, signer)
        issued = issue(csr)
        inner = degenerate([issued])
        env = _encrypt_envelope(inner, signer_a, enc_alg)
        info["status"] = "issued"
        info["serial"] = format(issued.serial_number, "x")
        return _cert_rep(ra_cert, ra_key, txid, nonce, SUCCESS, content=env), info
    except ScepError as e:
        info.update(status="rejected", reason=str(e))
        return _cert_rep(ra_cert, ra_key, txid, nonce, FAILURE, fail_info=e.fail_info), info
    except Exception as e:
        info.update(status="rejected", reason=f"bad request: {e}")
        return _cert_rep(ra_cert, ra_key, txid, nonce, FAILURE, fail_info=BAD_MESSAGE_CHECK), info
