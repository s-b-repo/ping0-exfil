#!/usr/bin/env python3

import socket
import struct
import hashlib
import sys

"""
A simple ICMP "server" that:
  - Listens for ICMP Echo Requests (type=8).
  - Expects custom payloads with this structure:

    [0..7]   = b"FILEXFER"
    [8]      = packet_type
               0 = START
               1 = DATA CHUNK
               2 = END
    [9..10]  = chunk_number (16-bit, network order)
    [11..42] = 32-byte chunk SHA-256 for the data chunk (or dummy for START/END)
    [43.. ]  = variable data:
               If packet_type=0 => filename
               If packet_type=1 => actual file chunk data
               If packet_type=2 => final file SHA-256 hex string

  - Verifies each chunk’s SHA-256 and, if valid, sends an "ACK" (type=0 echo-reply).
    If invalid, sends a "NACK" (type=0 echo-reply).
  - Assembles chunks into a file on-disk (writes sequentially).
  - When the final packet arrives, it compares the file’s overall SHA-256 to the declared
    final hash. If valid, finishes gracefully; otherwise logs an error.
"""

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0

# We'll define custom "packet_type" values in the replies to indicate ACK or NACK
# for easier parsing on the client side:
PACKET_TYPE_ACK  = 10
PACKET_TYPE_NACK = 11
PACKET_TYPE_DONE = 12  # final ACK after successful end

MAX_PACKET_SIZE  = 65535
SIGNATURE        = b"FILEXFER"
SIG_LEN          = len(SIGNATURE)

class TransferSession:
    """
    Holds transfer state for a single (client_ip, icmp_id) combination.
    We do "chunk-by-chunk" writing to disk to handle large files with minimal RAM usage.
    """
    def __init__(self):
        self.filename = None
        self.file_handle = None
        self.sha256 = hashlib.sha256()  # incremental hash of the entire file
        self.expected_chunk = 0         # we expect chunks in strict ascending order
        self.final_hash_hex = None
        self.done = False

    def close(self):
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None

# Global dictionary of active sessions keyed by (client_ip, icmp_id)
transfer_sessions = {}

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

def build_icmp_echo_reply(icmp_id, icmp_seq, payload: bytes) -> bytes:
    """
    Build ICMP Echo Reply (type=0) packet.
    The 'payload' should contain our custom data.
    """
    icmp_type = ICMP_ECHO_REPLY
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
    Returns (src_ip, icmp_type, icmp_code, icmp_id, icmp_seq, icmp_payload, ip_header_len) or None.
    """
    if len(packet) < 20:
        return None
    # parse IP header
    ver_ihl = packet[0]
    ihl = ver_ihl & 0x0F
    ip_header_len = ihl * 4
    if len(packet) < ip_header_len + 8:
        return None

    # extract ICMP header
    icmp_header = packet[ip_header_len : ip_header_len+8]
    icmp_type, icmp_code, icmp_cksum, icmp_id, icmp_seq = struct.unpack("!BBHHH", icmp_header)
    icmp_payload = packet[ip_header_len+8:]
    return (icmp_type, icmp_code, icmp_id, icmp_seq, icmp_payload, ip_header_len)

def handle_packet(sock, src_ip, icmp_id, icmp_seq, icmp_payload):
    """
    Handle our custom file-transfer protocol. Then send an ACK or NACK echo-reply back to the client.
    """
    # We expect at least the signature, plus 1 byte type, 2 bytes chunk#, 32 bytes chunk-hash
    if len(icmp_payload) < SIG_LEN + 1 + 2 + 32:
        return  # ignore invalid
    
    if icmp_payload[:SIG_LEN] != SIGNATURE:
        return  # ignore anything that doesn't start with "FILEXFER"

    pkt_type = icmp_payload[SIG_LEN]
    chunk_num = struct.unpack("!H", icmp_payload[SIG_LEN+1:SIG_LEN+3])[0]
    chunk_hash = icmp_payload[SIG_LEN+3 : SIG_LEN+3+32]
    data = icmp_payload[SIG_LEN+3+32 : ]

    session_key = (src_ip, icmp_id)
    if session_key not in transfer_sessions:
        transfer_sessions[session_key] = TransferSession()
    session = transfer_sessions[session_key]

    if pkt_type == 0:  # START
        filename = data.decode(errors='ignore').strip()
        session.filename = filename
        try:
            # Open for write (overwrite if exists). For extremely robust logic, you might want a safer approach.
            session.file_handle = open(filename, "wb")
            print(f"[+] New file transfer from {src_ip}: ID={icmp_id}, filename='{filename}'")
        except Exception as e:
            print(f"[!] Could not open file for writing: {e}")
            # We can't proceed. Mark session done or remove it.
            session.done = True
        
        # Acknowledge start (no chunk_data to check)
        reply_payload = (SIGNATURE
                         + struct.pack("!B", PACKET_TYPE_ACK)
                         + struct.pack("!H", chunk_num)
                         + b"\x00"*32  # dummy hash in ACK
                         + b"OK-START")
        reply = build_icmp_echo_reply(icmp_id, icmp_seq, reply_payload)
        sock.sendto(reply, (src_ip, 0))

    elif pkt_type == 1:  # DATA CHUNK
        if session.done or not session.file_handle:
            # If session is already closed or invalid, NACK
            reply_payload = (SIGNATURE
                             + struct.pack("!B", PACKET_TYPE_NACK)
                             + struct.pack("!H", chunk_num)
                             + b"\x00"*32
                             + b"Session invalid")
            reply = build_icmp_echo_reply(icmp_id, icmp_seq, reply_payload)
            sock.sendto(reply, (src_ip, 0))
            return
        
        # Check if chunk_num matches expected
        if chunk_num != session.expected_chunk:
            # If it's out of order, we NACK so client can retry
            msg = f"Expected chunk {session.expected_chunk}, got {chunk_num}"
            print(f"[!] {msg}, sending NACK.")
            reply_payload = (SIGNATURE
                             + struct.pack("!B", PACKET_TYPE_NACK)
                             + struct.pack("!H", chunk_num)
                             + b"\x00"*32
                             + msg.encode())
            reply = build_icmp_echo_reply(icmp_id, icmp_seq, reply_payload)
            sock.sendto(reply, (src_ip, 0))
            return

        # Verify chunk’s hash
        computed = hashlib.sha256(data).digest()
        if computed != chunk_hash:
            print(f"[!] Chunk {chunk_num} has invalid hash, sending NACK.")
            reply_payload = (SIGNATURE
                             + struct.pack("!B", PACKET_TYPE_NACK)
                             + struct.pack("!H", chunk_num)
                             + b"\x00"*32
                             + b"Chunk hash mismatch")
            reply = build_icmp_echo_reply(icmp_id, icmp_seq, reply_payload)
            sock.sendto(reply, (src_ip, 0))
            return

        # If valid, write to file
        session.file_handle.write(data)
        session.file_handle.flush()
        session.sha256.update(data)
        session.expected_chunk += 1

        # Send ACK
        reply_payload = (SIGNATURE
                         + struct.pack("!B", PACKET_TYPE_ACK)
                         + struct.pack("!H", chunk_num)
                         + b"\x00"*32
                         + b"OK-CHUNK")
        reply = build_icmp_echo_reply(icmp_id, icmp_seq, reply_payload)
        sock.sendto(reply, (src_ip, 0))
        print(f"[+] Received and wrote chunk {chunk_num}, size={len(data)} bytes.")

    elif pkt_type == 2:  # END
        # data should contain the final file's SHA-256 in hex
        final_hash = data.decode(errors='ignore').strip()
        session.final_hash_hex = final_hash

        # If the session or file handle is invalid, we cannot proceed
        if session.done or not session.file_handle:
            reply_payload = (SIGNATURE
                             + struct.pack("!B", PACKET_TYPE_NACK)
                             + struct.pack("!H", chunk_num)
                             + b"\x00"*32
                             + b"Session invalid on END")
            reply = build_icmp_echo_reply(icmp_id, icmp_seq, reply_payload)
            sock.sendto(reply, (src_ip, 0))
            return

        # Close file handle
        session.file_handle.close()
        session.file_handle = None

        # Compare final hashes
        computed_hex = session.sha256.hexdigest()
        if computed_hex.lower() == final_hash.lower():
            print(f"[+] File '{session.filename}' received successfully.")
            print(f"    Computed SHA-256: {computed_hex}")
        else:
            print(f"[!] Final file hash mismatch for '{session.filename}'!")
            print(f"    Computed: {computed_hex}")
            print(f"    Expected: {final_hash}")

        # Mark session done
        session.done = True

        # Send final ACK (or NACK if you want to indicate mismatch)
        # We'll send an ACK anyway. The client can interpret mismatch from log if needed.
        reply_payload = (SIGNATURE
                         + struct.pack("!B", PACKET_TYPE_DONE)  # final ack
                         + struct.pack("!H", chunk_num)
                         + b"\x00"*32
                         + b"OK-END")
        reply = build_icmp_echo_reply(icmp_id, icmp_seq, reply_payload)
        sock.sendto(reply, (src_ip, 0))
        print("[+] End of transfer acknowledged.\n")

        # Optionally delete session from dictionary to keep memory small
        del transfer_sessions[session_key]

def main():
    # Need root/admin to open raw socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("[!] Error: You must run this script as root/administrator to open raw ICMP sockets.")
        sys.exit(1)

    print("[*] ICMP server listening for incoming file transfers...")

    while True:
        packet, (src_ip, _) = sock.recvfrom(MAX_PACKET_SIZE)

        parsed = parse_ip_icmp(packet)
        if not parsed:
            continue

        icmp_type, icmp_code, icmp_id, icmp_seq, icmp_payload, ip_header_len = parsed
        # We only care about echo requests
        if icmp_type == ICMP_ECHO_REQUEST and icmp_code == 0:
            handle_packet(sock, src_ip, icmp_id, icmp_seq, icmp_payload)

if __name__ == "__main__":
    main()
