import struct

HEADER = b'\xAA\x55'


def hex_dump(data: bytes):
    return data.hex()


def ascii_dump(data: bytes):
    try:
        return data.decode(errors="ignore")
    except:
        return ""


def inspect_packet(packet: bytes):

    print("\n========== PACKET INSPECTOR ==========")

    packet_length = len(packet)
    print("Packet Size:", packet_length, "bytes")

    header = packet[:2]
    version = packet[2]
    node_id = packet[3]

    nonce = packet[4:16]
    tag = packet[-16:]
    ciphertext = packet[16:-16]

    print("\n--- HEADER ---")
    print("Header:", header.hex())

    if header == HEADER:
        print("Header Status: VALID")
    else:
        print("Header Status: INVALID")

    print("\n--- BASIC FIELDS ---")
    print("Version:", version)
    print("Node ID:", node_id)

    print("\n--- NONCE ---")
    print("Nonce Length:", len(nonce))
    print("Nonce:", nonce.hex())

    print("\n--- CIPHERTEXT ---")
    print("Ciphertext Length:", len(ciphertext))
    print("Ciphertext (HEX):", ciphertext.hex())
    print("Ciphertext (ASCII Preview):", ascii_dump(ciphertext))

    print("\n--- AUTH TAG ---")
    print("Tag Length:", len(tag))
    print("Tag:", tag.hex())

    print("\n--- STRUCTURE SUMMARY ---")
    print("Header:        bytes 0-1")
    print("Version:       byte 2")
    print("Node ID:       byte 3")
    print("Nonce:         bytes 4-15")
    print("Ciphertext:    bytes 16-", packet_length - 17)
    print("Tag:           last 16 bytes")

    print("======================================\n") 