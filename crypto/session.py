import hashlib


def derive_session_key(secret: bytes, nonce: bytes, timestamp: bytes = b""):
    return hashlib.sha256(secret + nonce + timestamp).digest()