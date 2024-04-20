import socket
import struct

MAX_IP_LEN = 16
MAX_MAC_LEN = 18


class ARPHeader:
    def __init__(self):
        self.hardware_type = 0x0001  # Ethernet
        self.protocol_type = 0x0800  # IPv4
        self.hardware_len = 6         # MAC address length
        self.protocol_len = 4         # IP address length
        self.opcode = 0x0001          # ARP Request
        self.sender_mac = b'\x00' * 6
        self.sender_ip = b'\x00' * 4
        self.sender_port = 0          # Sender port (new attribute)
        self.target_mac = b'\x00' * 6
        self.target_ip = b'\x00' * 4


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


class TrieNode:
    def __init__(self):
        self.next = {}
        self.output = None  # Represents MAC address associated with IP


trie = TrieNode()  # Root node of Trie


def insert_into_trie(ip, mac):
    node = trie
    for octet in ip.split('.'):
        if octet not in node.next:
            node.next[octet] = TrieNode()
        node = node.next[octet]
    node.output = mac


def lookup_mac_in_trie(ip):
    node = trie
    for octet in ip.split('.'):
        if octet not in node.next:
            return None
        node = node.next[octet]
    return node.output


MAC_DEVICE = 'aa:aa:aa:aa:aa:aa'


def handle_arp_request(arp_pkt, sender_ip_str, sender_port):
    sender_mac_str = lookup_mac_in_trie(sender_ip_str)
    if sender_mac_str:
        print(f"ARP Request received for IP: {sender_ip_str}")
        print(f"Sending ARP Reply with MAC: {sender_mac_str}")

        # Simulate sending ARP reply (construct and send reply packet)
        arp_reply = ARPHeader()
        arp_reply.sender_mac = bytes.fromhex(MAC_DEVICE.replace(':', ''))
        arp_reply.sender_ip = arp_pkt.target_ip
        arp_reply.sender_port = arp_pkt.sender_port  # Include sender port in reply
        arp_reply.target_mac = bytes.fromhex(sender_mac_str.replace(':', ''))
        arp_reply.target_ip = arp_pkt.sender_ip

        # Craft the ARP reply packet
        arp_packet = struct.pack('!HHBBH6s4s6s4sH',
                                 arp_reply.hardware_type,
                                 arp_reply.protocol_type,
                                 arp_reply.hardware_len,
                                 arp_reply.protocol_len,
                                 arp_reply.opcode,
                                 arp_reply.sender_mac,
                                 arp_reply.sender_ip,
                                 arp_reply.target_mac,
                                 arp_reply.target_ip,
                                 arp_reply.sender_port)

        # Create a UDP socket for sending the ARP reply
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # Send the ARP reply packet to the sender's IP address and port
            sock.sendto(arp_packet, (sender_ip_str, sender_port))
            print(f"ARP Reply sent to {sender_ip_str}:{sender_port}")
    else:
        print(f"No MAC address found for IP: {sender_ip_str}")


def process_requests():
    # Create UDP socket for receiving ARP requests
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind to all available interfaces on port 12345
    sockfd.bind(('0.0.0.0', 12345))
    sockfd.settimeout(5.0)  # Set a timeout of 5 seconds

    print(f"Server started on {'0.0.0.0'}:{12345}")

    while True:
        try:
            buffer, sender_addr = sockfd.recvfrom(1024)
            sender_ip_str = sender_addr[0]
            sender_port = sender_addr[1]

            arp_header = buffer_to_arp_header(buffer)
            if arp_header:
                # Handle ARP request or reply
                handle_arp_request(arp_header, sender_ip_str, sender_port)
            else:
                print("Invalid ARP packet received.")

        except socket.timeout:
            # Handle timeout (no data received within timeout period)
            print("Timeout: No data received within 5 seconds.")

        except Exception as e:
            # Handle other socket-related exceptions
            print(f"Socket error: {e}")
            break


if __name__ == "__main__":
    # Initialize Trie with IP to MAC mappings (for demonstration)
    insert_into_trie("192.168.1.100", "01:23:45:67:89:ab")
    insert_into_trie("10.0.0.1", "aa:bb:cc:dd:ee:ff")
    insert_into_trie("127.0.0.1", "aa:bb:cc:dd:ee:ff")

    # Start processing ARP requests
    process_requests()
