from protocol.packet_parser import parse_packet
from gateway.logger import logger


def receive_packet(packet: bytes):

    try:
        parsed = parse_packet(packet)

        # safe decoding
        try:
            sensor_data = parsed["sensor_data"].decode()
        except:
            sensor_data = str(parsed["sensor_data"])

        message = f"ACCEPTED | Node={parsed['node_id']} | Data={sensor_data}"

        print("\nPacket Accepted")
        print(message)

        logger.info(message)

        return parsed

    except Exception as e:

        error_msg = str(e) if str(e) else "Decryption/Auth failure"

        # improved classification
        if "nonce reused" in error_msg:
            reason = "Replay Attack"
        elif "header" in error_msg.lower():
            reason = "Invalid Header"
        elif "length" in error_msg.lower():
            reason = "Invalid Length"
        elif "expired" in error_msg.lower():
            reason = "Packet Expired"
        elif "timestamp" in error_msg.lower():
            reason = "Timestamp Error"
        elif "unknown node" in error_msg.lower():
            reason = "Invalid Node ID"
        else:
            reason = "Integrity/Decryption Failure"

        message = f"REJECTED | Type={reason} | Details={error_msg}"

        print("\nPacket Rejected")
        print(message)

        logger.warning(message)

        return None