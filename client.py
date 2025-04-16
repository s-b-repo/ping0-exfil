#!/usr/bin/env python3

import socket
import struct
import sys
import os
import hashlib
import time

"""
A simple ICMP "client" that:
  - Opens a raw ICMP socket for sending (and another for receiving echo-reply).
  - Sends a custom file-transfer sequence:
    0) START packet with filename
    1) Repeated DATA packets with chunked file data (each chunk has its own SHA-256)
       - Wait for ACK (or NACK) for each chunk; if NACK, re-send.
    2) END packet containing final SHA-256 hex of entire file.

  - On receiving each chunk’s echo-reply, parse it. If ACK => proceed; if NACK => re-send.
  - This linear chunk-by-chunk approach ensures we can correct corrupted chunks.
"""

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0

SIGNATURE = b"FILEXFER"
SIG_LEN   = len(SIGNATURE)

PACKET_TYPE_START = 0
PACKET_TYPE_DATA  = 1
PACKET_TYPE_END   = 2

PACKET_TYPE_ACK   = 10
PACKET_TYPE_NACK  = 11
PACKET_TYPE_DONE  = 12

CHUNK_SIZE        = 4096  # can tweak for performance
MAX_PACKET_SIZE   = 65535

def calc_icmp_checksum(data: bytes) -> int:
    """Compute the ICMP checksum (RFC 1071)."""
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
    Build ICMP Echo Request (type=8) with the given ID, sequence, and payload.
    """
    icmp_type = ICMP_ECHO_REQUEST
    icmp_code = 0
    dummy_cksum = 0
    header = struct.pack("!BBHHH", icmp_type, icmp_code, dummy_cksum, icmp_id, icmp_seq)
    packet = header + payload
    chksum = calc_icmp_checksum(packet)
    header = struct.pack("!BBHHH", icmp_type, icmp_code, chksum, icmp_id, icmp_seq)
    return header + payload

def parse_ip_icmp(packet: bytes):
    """
    Parse the IP header, then the ICMP header+payload.
    Returns (icmp_type, icmp_code, icmp_id, icmp_seq, icmp_payload) or None.
    """
    if len(packet) < 20:
        return None

    ver_ihl = packet[0]
    ihl = ver_ihl & 0x0F
    ip_header_len = ihl * 4
    if len(packet) < ip_header_len + 8:
        return None

    icmp_header = packet[ip_header_len : ip_header_len+8]
    icmp_type, icmp_code, icmp_cksum, icmp_id, icmp_seq = struct.unpack("!BBHHH", icmp_header)
    icmp_payload = packet[ip_header_len+8:]
    return (icmp_type, icmp_code, icmp_id, icmp_seq, icmp_payload)

def send_icmp_packet(sock_send, dest_ip, packet: bytes):
    """
    Send a raw ICMP packet to the given destination IP using an already-opened raw socket.
    """
    sock_send.sendto(packet, (dest_ip, 0))

def wait_for_reply(sock_recv, icmp_id, timeout=2.0):
    """
    Wait (up to 'timeout' seconds) for an ICMP Echo-Reply that matches our 'icmp_id'.
    Return (packet_type, chunk_number, info_str) if we see a valid FILEXFER payload,
    or None if timed out.
    """
    start_time = time.time()
    sock_recv.settimeout(timeout)
    while time.time() - start_time < timeout:
        try:
            packet, (src_ip, _) = sock_recv.recvfrom(MAX_PACKET_SIZE)
        except socket.timeout:
            return None
        parsed = parse_ip_icmp(packet)
        if not parsed:
            continue
        icmp_type, icmp_code, r_id, r_seq, icmp_payload = parsed
        # Must be echo-reply with the same ID
        if icmp_type != ICMP_ECHO_REPLY or r_id != icmp_id:
            continue
        # Must start with our signature
        if len(icmp_payload) < SIG_LEN + 1 + 2:
            continue
        if icmp_payload[:SIG_LEN] != SIGNATURE:
            continue
        p_type = icmp_payload[SIG_LEN]
        chunk_no = struct.unpack("!H", icmp_payload[SIG_LEN+1:SIG_LEN+3])[0]
        info = icmp_payload[SIG_LEN+3+32:]  # skip the 32 bytes of chunk-hash in the reply
        return (p_type, chunk_no, info)
    return None  # timed out

def send_file(dest_ip, filepath):
    # We’ll use a single ID for the whole transfer. Sequence increments for each packet.
    icmp_id = 0x1234
    icmp_seq = 1

    if not os.path.isfile(filepath):
        print(f"[!] '{filepath}' is not a valid file.")
        return
    filename = os.path.basename(filepath)

    # Open the file in binary read
    fsize = os.path.getsize(filepath)
    f_data_stream = open(filepath, "rb")

    # Precompute entire file’s hash for final check
    # (Alternatively, we can do this incrementally, but simpler to do up front for the demonstration.)
    with open(filepath, "rb") as tmpf:
        full_data = tmpf.read()
    final_hash_hex = hashlib.sha256(full_data).hexdigest()
    del full_data

    print(f"[*] Sending file: '{filename}' ({fsize} bytes) to {dest_ip}")
    print(f"    Full SHA-256: {final_hash_hex}")

    # Create one socket for sending, one for receiving
    # On Windows, you *must* run as Administrator; same on Linux with sudo or root
    try:
        sock_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("[!] Raw socket error: requires Administrator/Root privileges.")
        return

    # 1) Send START packet
    packet_type = PACKET_TYPE_START
    chunk_num = 0
    dummy_hash = b"\x00" * 32
    payload_start = (SIGNATURE
                     + struct.pack("!B", packet_type)
                     + struct.pack("!H", chunk_num)
                     + dummy_hash
                     + filename.encode('utf-8'))
    req_start = build_icmp_echo_request(icmp_id, icmp_seq, payload_start)
    send_icmp_packet(sock_send, dest_ip, req_start)

    # Wait for ACK
    for _ in range(5):  # up to 5 tries
        reply = wait_for_reply(sock_recv, icmp_id, timeout=3.0)
        if not reply:
            print("[!] No reply for START packet, retrying...")
            send_icmp_packet(sock_send, dest_ip, req_start)
            continue
        p_type, c_num, info_str = reply
        if p_type == PACKET_TYPE_ACK and c_num == chunk_num:
            print("[+] START acknowledged by server.")
            break
        elif p_type == PACKET_TYPE_NACK and c_num == chunk_num:
            print(f"[!] START NACK from server: {info_str}")
            print("    Resending START packet...")
            send_icmp_packet(sock_send, dest_ip, req_start)
            continue
    else:
        print("[!] Failed to get START ACK from server. Aborting.")
        f_data_stream.close()
        return

    icmp_seq += 1

    # 2) Send file chunks
    current_chunk = 0
    while True:
        chunk = f_data_stream.read(CHUNK_SIZE)
        if not chunk:
            break  # done reading
        # Build data packet
        chunk_hash = hashlib.sha256(chunk).digest()
        packet_type = PACKET_TYPE_DATA
        payload_data = (SIGNATURE
                        + struct.pack("!B", packet_type)
                        + struct.pack("!H", current_chunk)
                        + chunk_hash
                        + chunk)
        req_data = build_icmp_echo_request(icmp_id, icmp_seq, payload_data)

        # We’ll do a send-wait-for-ack loop for each chunk
        resend_attempts = 0
        while True:
            send_icmp_packet(sock_send, dest_ip, req_data)
            reply = wait_for_reply(sock_recv, icmp_id, timeout=3.0)
            if not reply:
                resend_attempts += 1
                if resend_attempts >= 5:
                    print(f"[!] No reply for chunk {current_chunk} after 5 attempts. Aborting.")
                    f_data_stream.close()
                    return
                print(f"[!] No reply for chunk {current_chunk}, retry #{resend_attempts} ...")
                continue
            p_type, c_num, info_str = reply
            if c_num != current_chunk:
                # Possibly an old reply or something else; ignore and retry
                print(f"[!] Received reply for chunk {c_num}, expected {current_chunk}. Ignoring.")
                continue
            if p_type == PACKET_TYPE_ACK:
                # Good, move on to next chunk
                print(f"[+] Chunk {current_chunk} ACK from server.")
                break
            elif p_type == PACKET_TYPE_NACK:
                print(f"[!] Chunk {current_chunk} NACK from server: {info_str}")
                print("    Resending the same chunk...")
                resend_attempts += 1
                if resend_attempts >= 10:
                    print(f"[!] Too many NACKs on chunk {current_chunk}, aborting.")
                    f_data_stream.close()
                    return
                continue
            else:
                print(f"[!] Unexpected reply type={p_type} for chunk {current_chunk}, ignoring/retrying.")
                resend_attempts += 1
                if resend_attempts >= 5:
                    print("[!] Too many unexpected replies, aborting.")
                    f_data_stream.close()
                    return

        current_chunk += 1
        icmp_seq += 1

    f_data_stream.close()

    # 3) Send END packet with final file hash
    packet_type = PACKET_TYPE_END
    chunk_num = 0xFFFF  # or any sentinel
    dummy_hash = b"\x00" * 32
    payload_end = (SIGNATURE
                   + struct.pack("!B", packet_type)
                   + struct.pack("!H", chunk_num)
                   + dummy_hash
                   + final_hash_hex.encode('utf-8'))
    req_end = build_icmp_echo_request(icmp_id, icmp_seq, payload_end)
    send_icmp_packet(sock_send, dest_ip, req_end)

    # Wait for final ack
    for _ in range(5):
        reply = wait_for_reply(sock_recv, icmp_id, timeout=3.0)
        if not reply:
            print("[!] No reply for END packet, retrying...")
            send_icmp_packet(sock_send, dest_ip, req_end)
            continue
        p_type, c_num, info_str = reply
        if p_type in (PACKET_TYPE_DONE, PACKET_TYPE_ACK) and c_num == chunk_num:
            print("[+] END acknowledged by server. Transfer complete.")
            break
        elif p_type == PACKET_TYPE_NACK and c_num == chunk_num:
            print(f"[!] END NACK from server: {info_str}")
            print("    Resending END packet...")
            send_icmp_packet(sock_send, dest_ip, req_end)
            continue
    else:
        print("[!] Failed to get END ACK from server after multiple attempts.")

    # Cleanup
    sock_send.close()
    sock_recv.close()

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <server_ip>")
        sys.exit(1)

    dest_ip = sys.argv[1].strip()
    filepath = input("Enter path of the file to send: ").strip()

    send_file(dest_ip, filepath)

if __name__ == "__main__":
    main()
