from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def generate_keypair():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key()

    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    return private, public_bytes


def derive_shared_secret(private_key, peer_public_bytes):

    peer_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        peer_public_bytes
    )

    return private_key.exchange(ec.ECDH(), peer_public)