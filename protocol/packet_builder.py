import time
import struct
import os

from config.settings import key_manager
from crypto.crypto import encrypt_payload
from crypto.session import derive_session_key
from crypto.auth import compute_response
from crypto.ecdh import generate_keypair

HEADER = b'\xAA\x55'
VERSION = 1

PACKET_TYPE_DATA = 1
PACKET_TYPE_KEY_UPDATE = 2
PACKET_TYPE_AUTH = 3
PACKET_TYPE_HELLO = 4

sequence_counter = {}
node_ecdh_private = {}


# ------------------------
# HELPERS
# ------------------------
def _get_seq(node_id):
    if node_id not in sequence_counter:
        sequence_counter[node_id] = 0
    sequence_counter[node_id] += 1
    return struct.pack(">I", sequence_counter[node_id])


def _get_time():
    ts = int(time.time())
    return ts, struct.pack(">I", ts)


# ------------------------
# DATA PACKET
# ------------------------
def build_packet(node_id, sensor_data):

    versions = key_manager.node_keys[node_id]
    key_version = max(versions.keys())
    key = versions[key_version]

    seq = _get_seq(node_id)
    _, timestamp = _get_time()

    nonce = os.urandom(12)

    session_key = derive_session_key(key, nonce, timestamp)

    aad = (
        HEADER +
        bytes([VERSION]) +
        bytes([node_id]) +
        bytes([key_version]) +
        bytes([PACKET_TYPE_DATA]) +
        seq +
        timestamp
    )

    ciphertext, tag = encrypt_payload(sensor_data, session_key, nonce, aad)

    return (
        HEADER +
        bytes([VERSION]) +
        bytes([node_id]) +
        bytes([key_version]) +
        bytes([PACKET_TYPE_DATA]) +
        seq +
        timestamp +
        nonce +
        ciphertext +
        tag
    )


# ------------------------
# KEY UPDATE PACKET
# ------------------------
def build_key_update_packet(node_id):

    versions = key_manager.node_keys[node_id]

    old_version = max(versions.keys())
    old_key = versions[old_version]

    new_version = old_version + 1
    new_key = os.urandom(32)

    seq = _get_seq(node_id)
    _, timestamp = _get_time()

    nonce = os.urandom(12)

    session_key = derive_session_key(old_key, nonce, timestamp)

    payload = bytes([new_version]) + new_key

    aad = (
        HEADER +
        bytes([VERSION]) +
        bytes([node_id]) +
        bytes([old_version]) +
        bytes([PACKET_TYPE_KEY_UPDATE]) +
        seq +
        timestamp
    )

    ciphertext, tag = encrypt_payload(payload, session_key, nonce, aad)

    return (
        HEADER +
        bytes([VERSION]) +
        bytes([node_id]) +
        bytes([old_version]) +
        bytes([PACKET_TYPE_KEY_UPDATE]) +
        seq +
        timestamp +
        nonce +
        ciphertext +
        tag
    )


# ------------------------
# AUTH PACKET
# ------------------------
def build_auth_packet(node_id, challenge):

    versions = key_manager.node_keys[node_id]
    key_version = max(versions.keys())
    key = versions[key_version]

    seq = _get_seq(node_id)
    _, timestamp = _get_time()

    nonce = os.urandom(12)

    response = compute_response(key, challenge)

    payload = challenge + response

    session_key = derive_session_key(key, nonce, timestamp)

    aad = (
        HEADER +
        bytes([VERSION]) +
        bytes([node_id]) +
        bytes([key_version]) +
        bytes([PACKET_TYPE_AUTH]) +
        seq +
        timestamp
    )

    ciphertext, tag = encrypt_payload(payload, session_key, nonce, aad)

    return (
        HEADER +
        bytes([VERSION]) +
        bytes([node_id]) +
        bytes([key_version]) +
        bytes([PACKET_TYPE_AUTH]) +
        seq +
        timestamp +
        nonce +
        ciphertext +
        tag
    )


# ------------------------
# HELLO (HANDSHAKE)
# ------------------------
def build_hello_packet(node_id):

    private, public = generate_keypair()
    node_ecdh_private[node_id] = private

    nonce = os.urandom(12)

    return (
        HEADER +
        bytes([VERSION]) +
        bytes([node_id]) +
        bytes([0]) +
        bytes([PACKET_TYPE_HELLO]) +
        public +
        nonce
    )