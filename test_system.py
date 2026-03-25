import time

from protocol.packet_builder import (
    build_packet,
    build_key_update_packet,
    build_hello_packet,
    build_auth_packet
)
from protocol.packet_parser import parse_packet

from crypto.auth import generate_challenge
from crypto.signature import verify_signature

from cryptography.hazmat.primitives.asymmetric import ec


DELAY = 0.05  # avoid rate limiting


# =========================
# TEST 1: NORMAL
# =========================
print("\n=== TEST 1: NORMAL PACKET ===")

packet = build_packet(1, b"Temperature=30")
result = parse_packet(packet)
print("Parsed:", result)

time.sleep(DELAY)


# =========================
# TEST 2: REPLAY
# =========================
print("\n=== TEST 2: REPLAY ATTACK ===")

packet = build_packet(1, b"Temperature=30")

print("First attempt:")
parse_packet(packet)

time.sleep(DELAY)

print("Replay attempt:")
try:
    parse_packet(packet)
except Exception as e:
    print("Blocked:", e)

time.sleep(DELAY)


# =========================
# TEST 3: KEY ROTATION
# =========================
print("\n=== TEST 3: KEY ROTATION ===")

packet1 = build_packet(1, b"Before Rotation")
print("Before rotation:", parse_packet(packet1))

time.sleep(DELAY)

update_packet = build_key_update_packet(1)
parse_packet(update_packet)

time.sleep(DELAY)

packet2 = build_packet(1, b"After Rotation")
print("After rotation:", parse_packet(packet2))

time.sleep(DELAY)


# =========================
# TEST 4: DOWNGRADE
# =========================
print("\n=== TEST 4: DOWNGRADE ATTACK ===")

update_packet = build_key_update_packet(1)
parse_packet(update_packet)

time.sleep(DELAY)

try:
    parse_packet(update_packet)
except Exception as e:
    print("Blocked:", e)

time.sleep(DELAY)


# =========================
# TEST 5: CORRUPTION
# =========================
print("\n=== TEST 5: CORRUPTED PACKET ===")

packet = build_packet(1, b"Temperature=30")

packet = bytearray(packet)
packet[10] ^= 0xFF
packet = bytes(packet)

try:
    parse_packet(packet)
except Exception as e:
    print("Blocked:", e)

time.sleep(DELAY)


# =========================
# TEST 6: WRONG KEY
# =========================
print("\n=== TEST 6: WRONG KEY ===")

packet = build_packet(1, b"Temperature=30")

packet = bytearray(packet)
packet[3] = 2
packet = bytes(packet)

try:
    parse_packet(packet)
except Exception as e:
    print("Blocked:", e)

time.sleep(DELAY)


# =========================
# TEST 7: DEVICE AUTH
# =========================
print("\n=== TEST 7: DEVICE AUTH ===")

challenge = generate_challenge()
packet = build_auth_packet(1, challenge)

result = parse_packet(packet)
print("Auth:", result)

time.sleep(DELAY)


# =========================
# TEST 8: HANDSHAKE
# =========================
print("\n=== TEST 8: HANDSHAKE ===")

packet = build_hello_packet(1)
result = parse_packet(packet)

print("Handshake:", result)

# ------------------------
# CORRECT SIGNATURE VERIFICATION
# ------------------------

sign_public_bytes = bytes.fromhex(result["sign_public"])
signature = bytes.fromhex(result["signature"])
data = bytes.fromhex(result["signed_data"])

gateway_pub = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP256R1(),
    sign_public_bytes
)

valid = verify_signature(gateway_pub, data, signature)

print("Signature valid:", valid)