"""
Data-at-rest encryption using AES-256-GCM (authenticated encryption).
Unchanged from original.
"""

import os
import base64
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

log = logging.getLogger("scms.crypto")

_NONCE_LEN  = 12
_PREFIX     = b"enc:"
_ENCODING   = "utf-8"

_raw_key_hex = os.environ.get("FIELD_ENCRYPTION_KEY", "")

def _derive_key(raw_hex: str) -> bytes | None:
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


def encryption_enabled() -> bool:
    return _FIELD_KEY is not None


def encrypt_field(plaintext: str | None) -> str | None:
    if not plaintext or not _FIELD_KEY:
        return plaintext
    try:
        pt_bytes = plaintext.encode(_ENCODING)
        nonce    = os.urandom(_NONCE_LEN)
        aesgcm   = AESGCM(_FIELD_KEY)
        ct       = aesgcm.encrypt(nonce, pt_bytes, None)
        blob     = _PREFIX + base64.urlsafe_b64encode(nonce + ct)
        return blob.decode("ascii")
    except Exception as exc:
        log.error("encrypt_field failed: %s", exc)
        return plaintext


def decrypt_field(ciphertext: str | None) -> str | None:
    if not ciphertext:
        return ciphertext
    if not ciphertext.startswith("enc:"):
        return ciphertext
    if not _FIELD_KEY:
        return "[encrypted — no key]"
    try:
        raw      = base64.urlsafe_b64decode(ciphertext[4:])
        nonce    = raw[:_NONCE_LEN]
        ct_tag   = raw[_NONCE_LEN:]
        aesgcm   = AESGCM(_FIELD_KEY)
        pt_bytes = aesgcm.decrypt(nonce, ct_tag, None)
        return pt_bytes.decode(_ENCODING)
    except Exception as exc:
        log.warning("decrypt_field failed (tampered ciphertext?): %s", exc)
        return "[decryption error]"


def encrypt_event(event: dict) -> dict:
    sensitive = ("Message", "RawLine", "UserName", "SourceIp")
    return {
        k: (encrypt_field(v) if k in sensitive and isinstance(v, str) else v)
        for k, v in event.items()
    }


def decrypt_event(event: dict) -> dict:
    sensitive = ("message", "rawline", "username", "sourceip",
                 "Message", "RawLine", "UserName", "SourceIp")
    return {
        k: (decrypt_field(v) if k in sensitive and isinstance(v, str) else v)
        for k, v in event.items()
    }
