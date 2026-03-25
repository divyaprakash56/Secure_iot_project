import time
import random
import os
import struct

from protocol.packet_builder import build_packet
from gateway.receiver import receive_packet
from config.settings import NODE_KEYS
from crypto.crypto import encrypt_payload


# ------------------------
# Utility Functions
# ------------------------

def generate_sensor_data():
    temp = random.randint(20, 40)
    return f"Temperature={temp}".encode()


def simulate_node(node_id):
    sensor_data = generate_sensor_data()
    packet = build_packet(node_id=node_id, sensor_data=sensor_data)
    return packet


# ------------------------
# Attack Functions
# ------------------------

def replay_attack(packet):
    print("\n[ATTACK] Replaying packet")
    receive_packet(packet)


def corrupt_packet(packet):
    packet = bytearray(packet)
    index = random.randint(0, len(packet) - 1)
    packet[index] ^= 0xFF
    print("\n[ATTACK] Corrupted packet")
    return bytes(packet)


def invalid_header(packet):
    packet = bytearray(packet)
    packet[0] = 0x00
    packet[1] = 0x00
    print("\n[ATTACK] Invalid header")
    return bytes(packet)


def random_noise_attack():
    print("\n[ATTACK] Random noise packet")
    fake_packet = os.urandom(50)
    receive_packet(fake_packet)


def partial_packet_attack(packet):
    print("\n[ATTACK] Partial packet")
    short_packet = packet[:10]
    receive_packet(short_packet)


def wrong_key_packet(node_id):
    print("\n[ATTACK] Wrong key used")

    # intentionally use wrong key (Node 1 key)
    wrong_key = NODE_KEYS.get(1)

    sensor_data = generate_sensor_data()

    timestamp = int(time.time())
    payload = struct.pack(">I", timestamp) + sensor_data

    aad = b'\xAA\x55' + bytes([1]) + bytes([node_id])

    nonce, ciphertext, tag = encrypt_payload(payload, wrong_key, aad)

    packet = (
        b'\xAA\x55' +
        bytes([1]) +
        bytes([node_id]) +
        nonce +
        ciphertext +
        tag
    )

    receive_packet(packet)


# ------------------------
# Simulation Loop
# ------------------------

def run_simulation(num_nodes=3, delay=1):

    print("\n=== Advanced Node Simulation Started ===\n")

    while True:

        node_id = random.randint(1, num_nodes)
        packet = simulate_node(node_id)

        attack_type = random.choice([
            "normal",
            "replay",
            "corrupt",
            "invalid",
            "noise",
            "partial",
            "wrong_key"
        ])

        print(f"\n[Node {node_id}] Mode: {attack_type}")

        if attack_type == "normal":
            receive_packet(packet)

        elif attack_type == "replay":
            receive_packet(packet)
            replay_attack(packet)

        elif attack_type == "corrupt":
            bad_packet = corrupt_packet(packet)
            receive_packet(bad_packet)

        elif attack_type == "invalid":
            bad_packet = invalid_header(packet)
            receive_packet(bad_packet)

        elif attack_type == "noise":
            random_noise_attack()

        elif attack_type == "partial":
            partial_packet_attack(packet)

        elif attack_type == "wrong_key":
            wrong_key_packet(node_id)

        time.sleep(delay)


# ------------------------
# Entry Point
# ------------------------

if __name__ == "__main__":
    try:
        run_simulation(num_nodes=5, delay=0.1)
    except KeyboardInterrupt:
        print("\nSimulation stopped safely.")