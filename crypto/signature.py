import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature
)


def generate_signing_keypair():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key()
    return private, public


def sign_data(private_key, data: bytes):
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature


def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())  # ✅ MUST MATCH SIGNING
        )
        return True
    except Exception:
        return False

KEY_FILE = "gateway_sign_key.pem"


def load_or_create_keys():

    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())

        with open(KEY_FILE, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

    public_key = private_key.public_key()

    return private_key, public_key