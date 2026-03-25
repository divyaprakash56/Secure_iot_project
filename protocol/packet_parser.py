import struct
import time

from config.settings import key_manager
from crypto.crypto import decrypt_payload
from crypto.session import derive_session_key
from crypto.auth import verify_response
from crypto.ecdh import generate_keypair, derive_shared_secret
from crypto.signature import generate_signing_keypair, sign_data
from crypto.signature import load_or_create_keys

from cryptography.hazmat.primitives import serialization

from security.replay_store import ReplayStore
from security.rate_limiter import rate_limiter
from security.secure_logger import secure_logger

HEADER = b'\xAA\x55'
node_id = 0  # default safe value
PACKET_TYPE_DATA = 1
PACKET_TYPE_KEY_UPDATE = 2
PACKET_TYPE_AUTH = 3
PACKET_TYPE_HELLO = 4

MIN_PACKET_SIZE = 42
MAX_PACKET_AGE = 60

replay_store = ReplayStore()
last_sequence = {}

# 🔐 ECDH keys
gateway_private, gateway_public_key = generate_keypair()

# 🔐 Signing keys
gateway_sign_private, gateway_sign_public = load_or_create_keys()

def reject(node_id, reason="generic"):
    secure_logger.log(f"REJECT node={node_id} reason={reason}")
    raise ValueError("Packet rejected")


def parse_packet(packet):

    # ------------------------
    # BASIC VALIDATION
    # ------------------------
    if not isinstance(packet, (bytes, bytearray)):
        reject(0)

    if len(packet) < 6:
        reject(0)

    if packet[:2] != HEADER:
        reject(0)

    # ------------------------
    # SAFE HEADER PARSING
    # ------------------------
    try:
        version = packet[2]
        node_id = packet[3]
        key_version = packet[4]
        packet_type = packet[5]
    except Exception:
        reject(0)

    # ------------------------
    # HANDSHAKE (CONTROL PLANE)
    # ------------------------
    if packet_type == PACKET_TYPE_HELLO:

        # strict size check
        if len(packet) < 83:
            reject(node_id, "handshake_len")

        try:
            node_public = packet[6:71]
            nonce = packet[71:83]

            # 🔐 ECDH
            shared_secret = derive_shared_secret(gateway_private, node_public)
            session_key = derive_session_key(shared_secret, nonce)

            # 🔐 Always derive public key bytes safely
            if isinstance(gateway_public_key, bytes):
                gateway_public_bytes = gateway_public_key
            else:
                gateway_public_bytes = gateway_public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )

            # 🔐 SIGN RAW HANDSHAKE PAYLOAD (bulletproof)
            node_public = packet[6:71]   # 65 bytes
            nonce = packet[71:83]        # 12 bytes

            handshake_payload = node_public + nonce
            data = node_public + nonce + gateway_public_bytes
            print("SIGN DATA LEN:", len(data))
            print("SIGN DATA:", data.hex())
            signature = sign_data(gateway_sign_private, data)

        except Exception as e:
            print("[DEBUG HANDSHAKE ERROR]:", e)
            reject(node_id, "handshake")

        print(f"[HANDSHAKE] Secure session with node {node_id}")
        secure_logger.log(f"HANDSHAKE node={node_id}")

        return {
            "type": "handshake",
            "node_id": node_id,
            "session_key": session_key.hex(),
            "gateway_public": gateway_public_bytes.hex(),
            "sign_public": gateway_sign_public.public_bytes(encoding=serialization.Encoding.X962,format=serialization.PublicFormat.UncompressedPoint).hex(),
            "signature": signature.hex(),
            "signed_data": data.hex()
        }

    # ------------------------
    # NORMAL PACKET FLOW
    # ------------------------
    if len(packet) < MIN_PACKET_SIZE:
        reject(node_id)

    try:
        seq = struct.unpack(">I", packet[6:10])[0]
        timestamp_bytes = packet[10:14]
        timestamp = struct.unpack(">I", timestamp_bytes)[0]

        nonce = packet[14:26]
        ciphertext = packet[26:-16]
        tag = packet[-16:]
    except Exception:
        reject(node_id)

    # ------------------------
    # RATE LIMIT
    # ------------------------
    if not rate_limiter.is_allowed(node_id):
        reject(node_id, "rate")

    # ------------------------
    # SEQUENCE CHECK
    # ------------------------
    if node_id in last_sequence and seq <= last_sequence[node_id]:
        reject(node_id, "sequence")

    last_sequence[node_id] = seq

    # ------------------------
    # REPLAY CHECK
    # ------------------------
    nonce_hex = nonce.hex()

    if replay_store.is_replay(node_id, nonce_hex):
        reject(node_id, "replay")

    # ------------------------
    # KEY FETCH
    # ------------------------
    try:
        key = key_manager.get_key(node_id, version=key_version)
    except Exception:
        reject(node_id, "key")

    # ------------------------
    # SESSION KEY
    # ------------------------
    session_key = derive_session_key(key, nonce, timestamp_bytes)
    aad = packet[:14]

    # ------------------------
    # DECRYPT
    # ------------------------
    try:
        payload = decrypt_payload(nonce, ciphertext, tag, session_key, aad)
    except Exception:
        secure_logger.log(f"REJECT node={node_id} reason=aes")
        raise ValueError("AES authentication failed")

    replay_store.add_nonce(node_id, nonce_hex)

    # ------------------------
    # AUTH PACKET
    # ------------------------
    if packet_type == PACKET_TYPE_AUTH:

        challenge = payload[:16]
        response = payload[16:]

        if not verify_response(key, challenge, response):
            reject(node_id, "auth")

        secure_logger.log(f"AUTH_SUCCESS node={node_id}")

        return {
            "type": "auth",
            "node_id": node_id,
            "status": "authenticated"
        }

    # ------------------------
    # KEY UPDATE
    # ------------------------
    if packet_type == PACKET_TYPE_KEY_UPDATE:

        new_version = payload[0]
        new_key = payload[1:]

        versions = key_manager.node_keys[node_id]

        if new_version <= max(versions.keys()):
            reject(node_id, "downgrade")

        versions[new_version] = new_key

        secure_logger.log(f"KEY_UPDATE node={node_id} v={new_version}")
        print(f"[SECURITY] Node {node_id} updated to key v{new_version}")

        return None

    # ------------------------
    # NORMAL DATA
    # ------------------------
    current_time = int(time.time())

    if timestamp > current_time + 5:
        reject(node_id, "future")

    if current_time - timestamp > MAX_PACKET_AGE:
        reject(node_id, "expired")

    secure_logger.log(f"ACCEPT node={node_id} seq={seq}")

    return {
        "version": version,
        "node_id": node_id,
        "sequence": seq,
        "timestamp": timestamp,
        "sensor_data": payload
    }