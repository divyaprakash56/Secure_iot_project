'''from crypto.encryption import encrypt_payload, decrypt_payload

data = b"Temperature=31"

print("Original:", data)

nonce, ciphertext, tag = encrypt_payload(data)

print("Nonce:", nonce)
print("Ciphertext:", ciphertext)
print("Tag:", tag)

decrypted = decrypt_payload(nonce, ciphertext, tag)

print("Decrypted:", decrypted)


from protocol.packet_builder import build_packet

sensor_data = b"Temperature=31"

packet = build_packet(node_id=1, sensor_data=sensor_data)

print("Packet Length:", len(packet))
print("Packet Bytes:", packet)


from protocol.packet_builder import build_packet
from protocol.packet_parser import parse_packet

sensor_data = b"Temperature=31"

# build packet
packet = build_packet(node_id=1, sensor_data=sensor_data)

print("Packet length:", len(packet))

# parse packet
parsed = parse_packet(packet)

print("\nParsed Packet")
print(parsed)


from protocol.packet_builder import build_packet
from protocol.packet_parser import parse_packet

sensor_data = b"Temperature=31"

packet = build_packet(node_id=1, sensor_data=sensor_data)

print("First parse:")
print(parse_packet(packet))

print("\nReplay attempt:")
print(parse_packet(packet))



from protocol.packet_builder import build_packet
from gateway.receiver import receive_packet


sensor_data = b"Temperature=31"

packet = build_packet(node_id=1, sensor_data=sensor_data)

print("Sending packet to gateway...")

receive_packet(packet)

print("\nReplaying packet...")

receive_packet(packet)


from protocol.packet_builder import build_packet
from protocol.debugger import inspect_packet
from gateway.receiver import receive_packet

sensor_data = b"Temperature=31"

packet = build_packet(node_id=1, sensor_data=sensor_data)

# full packet inspection
inspect_packet(packet)

# send to gateway
receive_packet(packet)'''
#upar ke code testing ke liye the aur jo niche hai vo real gateway program ke liye hai 
import time
from protocol.packet_builder import build_packet
from protocol.debugger import inspect_packet
from gateway.receiver import receive_packet
def start_gateway():

    print("\n==============================")
    print(" Secure LoRa Gateway Starting ")
    print("==============================\n")

    print("Gateway initialized.")
    print("Waiting for packets...\n")

    while True:

        # Simulated sensor data (later will come from LoRa)
        sensor_data = b"Temperature=31"

        # Simulated packet from node
        packet = build_packet(node_id=1, sensor_data=sensor_data)

        print("\nPacket received!\n")

        # Debug inspector
        inspect_packet(packet)

        # Send packet to gateway processing
        receive_packet(packet)

        # simulate network delay
        time.sleep(5)


if __name__ == "__main__":
    start_gateway()