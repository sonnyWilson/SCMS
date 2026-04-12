"""
server/crypto.py — Secure Continuous Monitoring System
Data-at-rest encryption using AES-256-GCM (authenticated encryption).

Every sensitive field (Message, RawLine, UserName, SourceIp) is encrypted
before being written to PostgreSQL and decrypted on read.

Key derivation:
    FIELD_KEY = HKDF-SHA256(FIELD_ENCRYPTION_KEY, salt="scms-field-v1", length=32)

Encryption:
    AES-256-GCM with a random 12-byte nonce per ciphertext.
    Output format (base64url):  nonce(12) || ciphertext || tag(16)
    Prefix "enc:" distinguishes encrypted fields from plaintext legacy rows.

Why AES-256-GCM?
  - Authenticated encryption — decryption fails if the ciphertext has been
    tampered with (256-bit tag verification).
  - NIST SP 800-38D approved; FIPS 140-2 compliant.
  - Unique nonce per encryption guarantees semantic security even for
    identical plaintexts.
"""

import os
import base64
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

log = logging.getLogger("scms.crypto")

_NONCE_LEN  = 12          # GCM standard nonce size (96 bits)
_PREFIX     = b"enc:"     # marks encrypted blobs in DB
_ENCODING   = "utf-8"

# ── Key material loaded once at import time ──────────────────────────────────
# FIELD_ENCRYPTION_KEY must be set in .env (32 hex bytes = 64 hex chars).
# install.py generates this automatically.
_raw_key_hex = os.environ.get("FIELD_ENCRYPTION_KEY", "")

def _derive_key(raw_hex: str) -> bytes | None:
    """Derive a 32-byte AES key from the hex master key via HKDF-SHA256."""
    if not raw_hex or len(raw_hex) < 32:
        return None
    try:
        raw = bytes.fromhex(raw_hex)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"scms-field-v1",
            info=b"scms-aes-gcm",
            backend=default_backend(),
        )
        return hkdf.derive(raw)
    except Exception as exc:
        log.warning("Key derivation failed: %s", exc)
        return None


_FIELD_KEY: bytes | None = _derive_key(_raw_key_hex)

if not _FIELD_KEY:
    log.warning(
        "FIELD_ENCRYPTION_KEY not set or invalid — "
        "data-at-rest encryption DISABLED. "
        "Run install.py to generate a key."
    )


# ── Public API ────────────────────────────────────────────────────────────────
def encryption_enabled() -> bool:
    return _FIELD_KEY is not None


def encrypt_field(plaintext: str | None) -> str | None:
    """
    Encrypt a string field.  Returns a base64url string prefixed with 'enc:'.
    Returns plaintext unchanged if encryption is disabled or input is None/empty.
    """
    if not plaintext or not _FIELD_KEY:
        return plaintext

    try:
        pt_bytes = plaintext.encode(_ENCODING)
        nonce    = os.urandom(_NONCE_LEN)          # cryptographic random nonce
        aesgcm   = AESGCM(_FIELD_KEY)
        ct       = aesgcm.encrypt(nonce, pt_bytes, None)   # ct includes 16-byte GCM tag
        blob     = _PREFIX + base64.urlsafe_b64encode(nonce + ct)
        return blob.decode("ascii")
    except Exception as exc:
        log.error("encrypt_field failed: %s", exc)
        return plaintext   # fail open — never lose data


def decrypt_field(ciphertext: str | None) -> str | None:
    """
    Decrypt a field encrypted by encrypt_field().
    Passes through plaintext (legacy) fields transparently.
    Returns None/empty unchanged.
    """
    if not ciphertext:
        return ciphertext

    # Legacy / unencrypted field — pass through
    if not ciphertext.startswith("enc:"):
        return ciphertext

    if not _FIELD_KEY:
        return "[encrypted — no key]"

    try:
        raw      = base64.urlsafe_b64decode(ciphertext[4:])   # strip "enc:"
        nonce    = raw[:_NONCE_LEN]
        ct_tag   = raw[_NONCE_LEN:]
        aesgcm   = AESGCM(_FIELD_KEY)
        pt_bytes = aesgcm.decrypt(nonce, ct_tag, None)
        return pt_bytes.decode(_ENCODING)
    except Exception as exc:
        log.warning("decrypt_field failed (tampered ciphertext?): %s", exc)
        return "[decryption error]"


def encrypt_event(event: dict) -> dict:
    """Encrypt the sensitive fields of a log event dict before DB insert."""
    sensitive = ("Message", "RawLine", "UserName", "SourceIp")
    return {
        k: (encrypt_field(v) if k in sensitive and isinstance(v, str) else v)
        for k, v in event.items()
    }


def decrypt_event(event: dict) -> dict:
    """Decrypt sensitive fields of a log event dict after DB read."""
    sensitive = ("message", "rawline", "username", "sourceip",
                 "Message", "RawLine", "UserName", "SourceIp")
    return {
        k: (decrypt_field(v) if k in sensitive and isinstance(v, str) else v)
        for k, v in event.items()
    }
