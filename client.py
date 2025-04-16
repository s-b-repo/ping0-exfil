#!/usr/bin/env python3

import socket
import struct
import os
import sys
import hashlib

# Adjust chunk size for the actual file data portion
CHUNK_SIZE = 1024

def calc_icmp_checksum(data: bytes) -> int:
    """
    Compute the ICMP checksum.
    """
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def build_icmp_echo_request(icmp_id, icmp_seq, payload: bytes) -> bytes:
    """
    Build a raw ICMP echo request packet with given ID, sequence, and payload.
    """
    # ICMP header: type (8), code (0), checksum (2 bytes), id (2 bytes), seq (2 bytes)
    icmp_type = 8
    icmp_code = 0
    dummy_cksum = 0
    header = struct.pack("!BBHHH", icmp_type, icmp_code, dummy_cksum, icmp_id, icmp_seq)
    packet = header + payload
    chksum = calc_icmp_checksum(packet)
    # Rebuild with real checksum
    header = struct.pack("!BBHHH", icmp_type, icmp_code, chksum, icmp_id, icmp_seq)
    return header + payload

def send_icmp_packet(dest_ip, packet: bytes):
    """
    Send a raw ICMP packet to destination IP.
    """
    # On Windows, protocol might be socket.IPPROTO_ICMP or socket.IPPROTO_IP, 
    # depending on privileges. Typically IPPROTO_ICMP is correct for Linux.
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.sendto(packet, (dest_ip, 0))

def send_file_over_icmp(dest_ip, filepath):
    """
    Reads a file, splits into chunks, sends:
     - start packet (packet_type=0, includes filename)
     - data packets (packet_type=1) for each chunk
     - end packet (packet_type=2) with final file hash
    """
    if not os.path.isfile(filepath):
        print(f"[!] Error: '{filepath}' is not a file.")
        return
    
    filename = os.path.basename(filepath)
    # Make a random ID, or constant for simplicity
    icmp_id = 1234
    icmp_seq = 1
    
    # Read entire file
    with open(filepath, "rb") as f:
        file_data = f.read()
    
    file_hash_hex = hashlib.sha256(file_data).hexdigest()
    
    # 1) Send Start Packet
    # Payload layout:
    #   8 bytes signature: "FILEXFER"
    #   1 byte packet_type=0
    #   2 bytes chunk_number=0
    #   32 bytes chunk_hash (we can just fill zeros for the start packet)
    #   remainder: filename
    signature = b"FILEXFER"
    packet_type = 0
    chunk_number = 0
    dummy_hash = b"\x00" * 32
    payload = (signature 
               + struct.pack("!B", packet_type) 
               + struct.pack("!H", chunk_number) 
               + dummy_hash 
               + filename.encode())
    icmp_req = build_icmp_echo_request(icmp_id, icmp_seq, payload)
    send_icmp_packet(dest_ip, icmp_req)
    print(f"[+] Sent start packet with filename='{filename}'")
    icmp_seq += 1
    
    # 2) Send Data Packets
    offset = 0
    chunk_num = 1
    while offset < len(file_data):
        chunk = file_data[offset:offset + CHUNK_SIZE]
        offset += CHUNK_SIZE
        
        chunk_hash = hashlib.sha256(chunk).digest()
        packet_type = 1
        payload = (signature
                   + struct.pack("!B", packet_type)
                   + struct.pack("!H", chunk_num)
                   + chunk_hash
                   + chunk)
        icmp_req = build_icmp_echo_request(icmp_id, icmp_seq, payload)
        send_icmp_packet(dest_ip, icmp_req)
        print(f"[+] Sent chunk {chunk_num}, size={len(chunk)} bytes.")
        chunk_num += 1
        icmp_seq += 1
    
    # 3) Send End Packet
    # The remainder includes the final SHA-256 hex digest for the entire file
    packet_type = 2
    # We'll put dummy chunk=0 for the end packet
    chunk_number = 0
    dummy_hash = b"\x00" * 32
    payload = (signature
               + struct.pack("!B", packet_type)
               + struct.pack("!H", chunk_number)
               + dummy_hash
               + file_hash_hex.encode())
    icmp_req = build_icmp_echo_request(icmp_id, icmp_seq, payload)
    send_icmp_packet(dest_ip, icmp_req)
    print("[+] Sent end packet.")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <destination_ip>")
        sys.exit(1)
    
    dest_ip = sys.argv[1].strip()
    # Ask the user for the path of the file to send
    filepath = input("Enter path of file to send: ").strip()
    
    print(f"[*] Sending file '{filepath}' to {dest_ip} via ICMP ...")
    send_file_over_icmp(dest_ip, filepath)
    print("[*] Done.")

if __name__ == "__main__":
    main()
