from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_payload(data: bytes, key: bytes, nonce: bytes, aad: bytes = None):

    aesgcm = AESGCM(key)

    encrypted = aesgcm.encrypt(nonce, data, aad)

    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]

    return ciphertext, tag


def decrypt_payload(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes, aad: bytes = None):

    aesgcm = AESGCM(key)

    encrypted = ciphertext + tag

    plaintext = aesgcm.decrypt(nonce, encrypted, aad)

    return plaintext