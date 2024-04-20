import socket
import struct


class ARPHeader:
    def __init__(self):
        self.hardware_type = 0x0001  # Ethernet
        self.protocol_type = 0x0800  # IPv4
        self.hardware_len = 6         # MAC address length
        self.protocol_len = 4         # IP address length
        self.opcode = 0x0001          # ARP Request
        self.sender_mac = b'\x00' * 6
        self.sender_ip = b'\x00' * 4
        self.sender_port = 12345      # Sender port


def buffer_to_arp_header(buffer):
    if len(buffer) >= struct.calcsize('!HHBBH6s4s6s4sH'):
        fields = struct.unpack('!HHBBH6s4s6s4sH', buffer)
        arp_header = ARPHeader()
        arp_header.hardware_type = fields[0]
        arp_header.protocol_type = fields[1]
        arp_header.hardware_len = fields[2]
        arp_header.protocol_len = fields[3]
        arp_header.opcode = fields[4]
        arp_header.sender_mac = fields[5]
        arp_header.sender_ip = fields[6]
        arp_header.target_mac = fields[7]
        arp_header.target_ip = fields[8]
        arp_header.sender_port = fields[9]
        return arp_header
    return None


def send_arp_request(target_ip_str):
    arp_pkt = ARPHeader()
    # Set sender MAC (change as needed)
    arp_pkt.sender_mac = b'\x00\x11\x22\x33\x44\x55'
    # Set sender IP (change as needed)
    arp_pkt.sender_ip = socket.inet_aton("192.168.1.10")
    arp_pkt.target_mac = b'\x00' * 6
    arp_pkt.target_ip = socket.inet_aton(target_ip_str)

    # Craft the ARP request packet
    arp_packet = struct.pack('!HHBBH6s4s6s4sH',
                             arp_pkt.hardware_type,
                             arp_pkt.protocol_type,
                             arp_pkt.hardware_len,
                             arp_pkt.protocol_len,
                             arp_pkt.opcode,
                             arp_pkt.sender_mac,
                             arp_pkt.sender_ip,
                             arp_pkt.target_mac,
                             arp_pkt.target_ip,
                             arp_pkt.sender_port)

    # Create a UDP socket for sending the ARP request
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Send the ARP request packet to the target IP address and port 12345
        sock.sendto(arp_packet, (target_ip_str, 12345))
        print(f"ARP Request sent to {target_ip_str}:12345")
    # Set a timeout for receiving the response (in seconds)
        sock.settimeout(5.0)

        try:
            # Wait to receive a response (ARP reply) from the server
            response, server_addr = sock.recvfrom(1024)
            print(f"ARP Reply received from {server_addr[0]}:{server_addr[1]}")

            arp_reply = buffer_to_arp_header(response)

            # Handle the ARP reply (process the received information)
            print(
                f"Sender MAC address: {':'.join(f'{b:02x}' for b in arp_reply.target_mac)}")

        except socket.timeout:
            print("Timeout: No ARP Reply received within 5 seconds.")

        except struct.error:
            print("Error: Invalid ARP Reply packet received.")


if __name__ == "__main__":
    # Specify the target IP address for the ARP request
    target_ip = "0.0.0.0"

    # Send ARP request to the target IP
    send_arp_request(target_ip)
