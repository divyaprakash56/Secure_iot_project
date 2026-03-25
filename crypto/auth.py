import hmac
import hashlib
import os


def generate_challenge():
    return os.urandom(16)


def compute_response(key: bytes, challenge: bytes):
    return hmac.new(key, challenge, hashlib.sha256).digest()


def verify_response(key: bytes, challenge: bytes, response: bytes):
    expected = compute_response(key, challenge)
    return hmac.compare_digest(expected, response)