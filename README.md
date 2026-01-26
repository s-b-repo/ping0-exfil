ICMP Toolkit - ping0-exfil

This repository contains a suite of tools for transferring files and executing remote commands over the ICMP (Internet Control Message Protocol). These tools utilize raw sockets to tunnel data within standard ICMP echo requests and replies, allowing for communication in environments where traditional TCP/UDP ports may be restricted.
Project Overview

The project is divided into two main functional systems:

    File Transfer System: For covertly exfiltrating or moving files.

    Remote Command Execution System: For running shell commands and receiving output via ICMP.

Requirements

    Python 3.x

    Root or Administrator privileges (required to open raw sockets for ICMP)

    Supported Platforms: Linux, Windows, macOS

Components

### 1. File Transfer System

This system handles chunk-by-chunk file transmission with SHA-256 integrity verification.
```
    server.py: The receiver script. It listens for ICMP packets with the FILEXFER signature, assembles file chunks in order, and verifies the final file hash.

    client.py: The sender script. It reads a local file, splits it into chunks, calculates hashes, and transmits them to the target IP.
```
### 2. Remote Command Execution System

This system allows for a "ping-based" shell where commands are sent in echo requests and results are returned in echo replies.
```
    executor.py: The listener script (server). It waits for ICMP packets containing a command signature, executes the command on the local system using a shell, and sends the stdout/stderr back in the ICMP reply.

    execute.py: The controller script (client). It sends a specific command to a target IP and waits to capture and display the returned output from the ICMP reply.
```
Usage Instructions
File Transfer

To receive a file: sudo python3 server.py
```
To send a file: sudo python3 client.py <target_ip> <path_to_file>
```
Remote Command Execution

To start the listener on the target machine: sudo python3 executor.py

To execute a command from the controller machine: sudo python3 execute.py <target_ip> "your_command_here"
Protocol Details

The tools use a custom header prepended to the ICMP payload:

    Signature: A unique string (e.g., FILEXFER or RUN_CMD) used to identify project packets.

    Type/Command: Identifies if the packet is a start, data chunk, end, or command execution request.

    Metadata: Includes chunk numbers and SHA-256 hashes for integrity and ordering.

Security Considerations

    No Encryption: By default, the data is sent in cleartext within the ICMP payload. It can be inspected by packet sniffers like Wireshark.

    No Authentication: The current version of the command executor does not require a password. Anyone who knows the packet signature can execute commands on the listener.

    Detection: While ICMP traffic is often allowed, high-frequency pings or large ICMP payloads may be flagged by Intrusion Detection Systems (IDS).

Disclaimer

This toolkit is intended for educational purposes, authorized security testing, and Red Team engagements only. Unauthorized use of these tools against systems you do not have explicit permission to test is illegal and unethical. The authors are not responsible for any misuse or damage caused by this software.
License

This project is licensed under the MIT License. See the LICENSE file for details.
