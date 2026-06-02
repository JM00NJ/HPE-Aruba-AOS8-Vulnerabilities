> ⚠️ **Disclosure Status:** All findings in this repository were submitted 
> to the HPE Networking Bug Bounty Program (Bugcrowd) between May–June 2026. 
> Five of six submissions were closed as "Not Applicable" at triage level 
> without technical reconciliation of the submitted evidence. 
> **No fixes have been issued as of June 2026.**


# Sources full write-up
https://netacoding.com/posts/ghost-leak/

https://netacoding.com/posts/smurf-reflection/

https://netacoding.com/posts/xxe-ssrf/


# HPE-Aruba-AOS8-Vulnerabilities
ArubaOS 8.13.2.0 pre-auth attack surface research. XXE+SSRF, ICMP  reflection, buffer over-read, hardcoded credentials — all submitted to  HPE Bugcrowd, marked N/A. No fixes issued.


# ArubaOS 8.13.2.0 Security Research

**Researcher:** Vesqer / JM00NJ  
**Blog:** [netacoding.com](https://netacoding.com)  
**Target:** HPE Aruba Networking Wireless — AOS-8 Controller  
**Version:** ArubaOS 8.13.2.0 LSR (Build 95415, compiled 2026-03-25)  
**Model:** ArubaMC-VA-US  
**Program:** HPE Networking Product Public Program (Bugcrowd)  
**Research period:** May–June 2026  

---

## Overview

This repository documents security research conducted on ArubaOS 8.13.2.0 LSR as part of the HPE Networking Bug Bounty Program on Bugcrowd. All research was performed on an authorized lab instance (ArubaMC-VA-US virtual machine) using the firmware images and OVA provided by the program at the official firmware link.

Six vulnerabilities were identified and submitted. The findings span the ICMP IP stack, the XML management interface (port 32000), and the FTP service (port 21). All testing was pre-authentication — no admin credentials or active sessions were used for any finding documented here.

---

## Findings

| # | Title | Submission | CWE | CVSS | Status |
|---|-------|------------|-----|------|--------|
| 1 | [Pre-Auth XXE → HTTP SSRF](01-xxe-http-ssrf/writeup.md) | 9e946ca3 | CWE-611 | 9.3 Critical | N/A — RaR expired unanswered |
| 2 | [ICMP Reflection + Smurf](02-smurf-reflection/writeup.md) | 09e49fa1 | CWE-290, CWE-406 | 7.4 High | N/A — RaR pending |
| 3 | [Ghost Leak](03-ghost-leak/writeup.md) | c5eda0ae | CWE-126, CWE-1284, CWE-354 | 6.5 Medium | N/A — RaR submitted |
| 4 | Pre-Auth XXE → FTP SSRF with RETR | 0c716fec | CWE-611 | — | Pending external review |
| 5 | Hardcoded FTP Credential (sap:x, CWE-798) | d13d0e83 | CWE-798, CWE-125 | — | Active — awaiting vendor response |
| 6 | ICMP Payload Relay — Zero DPI | b5727197 | CWE-20, CWE-693 | — | N/A |

Findings 4 and 5 are not published here pending resolution through active disclosure channels.

---

## Attack Surface

All documented findings are pre-authentication. The attack surface consists of three components:

```
ArubaOS 8.13.2.0 LSR
│
├── Port 32000/TCP  XML Management Interface
│   ├── [1] Pre-auth XXE → HTTP SSRF        (9e946ca3)
│   └── [4] Pre-auth XXE → FTP SSRF         (0c716fec) [pending]
│
├── IP/ICMP Stack
│   ├── [2] ICMP Reflection + Smurf          (09e49fa1)
│   ├── [3] Ghost Leak — IP Length over-read (c5eda0ae)
│   └── [6] ICMP Payload Relay / Zero DPI    (b5727197)
│
└── Port 21/TCP  FTP Service (vsftpd)
    └── [5] Hardcoded credential sap:x       (d13d0e83) [pending]
```

---

## Technical Summary

### Finding 1 — Pre-Auth XXE → HTTP SSRF

The XML parser on port 32000 resolves `SYSTEM` external entity declarations without authentication. Confirmed via:
- Wire-level packet capture: controller-initiated `GET /test HTTP/1.0` to attacker infrastructure
- Target system's own sshd log: `Bad protocol version identification 'GET / HTTP/1.0' from 127.0.0.1` — server-side evidence of SSRF execution recorded by the controller itself
- External DTD fetched 3 independent times from attacker HTTP server
- 9 internal ports confirmed open via `<dialog>success</dialog>` SSRF responses

Triage response: *"theoretical / no valid PoC"* — not addressed after four evidence items including the sshd log. First RaR expired without response.

---

### Finding 2 — ICMP Reflection + Smurf Amplification

The ICMP Echo handler does not validate source IP addresses against ARP table bindings or apply reverse path filtering (BCP38/uRPF). Spoofed ICMP Echo Requests cause the controller to deliver unsolicited replies to the spoofed source. Broadcast source addresses cause the controller to reply to `ff:ff:ff:ff:ff:ff`, delivering the reply to all hosts on the L2 segment.

Evidence: Two independent packet captures from two physically separate machines. Victim-side capture shows unsolicited Echo Reply at a host that sent zero ICMP requests.

Triage response: *"expected network functionality"* — the victim-side pcap was not addressed.

---

### Finding 3 — Ghost Leak (TTL=0 + IP Total Length Over-read)

The ICMP Echo handler trusts `IP_Total_Length` without validating against actual received frame size. Sending `IP_Total_Length=46` with actual IP data of 28 bytes causes the handler to read 18 bytes beyond the packet boundary from the network receive buffer, echoing those bytes in the reply.

The attack uses `TTL=0` packets (RFC 791 mandates discard) making it invisible to routers, IDS, firewalls, and logging systems. 27/27 TTL=0 crafted packets received replies — 100% response rate.

Same mechanism as CVE-2003-0001 (EtherLeak) and CVE-2021-3031 (Palo Alto PAN-OS), both accepted by their respective vendors.

Triage response: *"only zeroed bytes"* — attributing the VirtualBox virtual NIC clean padding characteristic to absence of vulnerability.

---

## Firmware Analysis

As part of the research into finding 5 (not published here), the AP firmware images distributed via the FTP service were reverse engineered. Key findings from static analysis of all four firmware images:

**Firmware format:** Aruba Image Container (`.ari`) — LZMA compressed, not encrypted. Body uses code signing (X.509) rather than confidentiality encryption.

**AP platforms covered:**

| File | Platform | SoC | Arch | Kernel | AP Models |
|------|----------|-----|------|--------|-----------|
| ipq40xx.ari | 30x | Qualcomm IPQ40xx | ARM32 Cortex-A7 | Linux 3.12.19-rt30 | AP-303/303H/303P/304/305/365/367 |
| ipq806x.ari | 32x | Qualcomm IPQ806x | ARM32 Cortex-A7 | Linux 3.12.19-rt30 | IPQ806x series |
| arm64.ari | 51x | Broadcom BCM94908 | ARM64 Cortex-A53 | Linux 4.1.45 | ARM64 AP series |
| ipq807x.ari | 53x | Qualcomm IPQ8074 | ARM64 Cortex-A53 | Linux 4.1.45 | AP-534/535/555/584/587 |

**Notable firmware findings:**

- All four firmware images contain cleartext X.509 DER certificates at end-of-file, signed by *Aruba Networks Code Signing CA1*, with Subject CN format `ARUBA-PROD-{SERIAL}::{MAC}` embedding real production AP MAC addresses
- The same two certificates appear across all four firmware platforms (cross-platform identity reuse)
- Linux 3.12.19 (ARM32 APs) — EOL since 2014. Linux 4.1.45 (ARM64 APs) — EOL since ~2022
- `arm64.ari` contains `/dev/tpm-cert` (TPM chip), MACsec hardware (EIP-62/EIP-217), `gponPassword` function
- Internal AP codenames exposed in firmware strings: `Glenmorangie` (AP-304/305), `Aberlour` (AP-303H), `Bunker` (AP-365/367), `Aultmore` (AP-555), `Hendricks` (AP-58x)
- Build server hostnames exposed: `jenkins@c96556966d48`, `jenkins@317fcb08bd82`, `jenkins@aec499ab9b0f`, `jenkins@352b80449f0a`

---

## Timeline

| Date | Event |
|------|-------|
| 06 May 2026 | XXE → HTTP SSRF submitted (9e946ca3) |
| 07 May 2026 | XXE → FTP SSRF submitted (0c716fec) |
| 10 May 2026 | 9e946ca3 closed N/A — "theoretical" |
| 14 May 2026 | Hardcoded FTP credential submitted (d13d0e83) |
| 15 May 2026 | Smurf/Reflection submitted (09e49fa1) |
| 15 May 2026 | Ghost Leak submitted (c5eda0ae) |
| 15 May 2026 | ICMP DPI Relay submitted (b5727197) |
| 19 May 2026 | d13d0e83 forwarded to HPE security team |
| 11 May 2026 | RaR on 9e946ca3 submitted |
| 21 May 2026 | Formal RaR response on 9e946ca3 — all 4 evidence items cited |
| 27 May 2026 | **RaR on 9e946ca3 expired without response** |
| 28 May 2026 | Second and final RaR on 9e946ca3 submitted |
| 01 Jun 2026 | 09e49fa1, c5eda0ae, b5727197 all closed N/A same day |
| 01 Jun 2026 | RaRs submitted on 09e49fa1 and c5eda0ae |
| 01 Jun 2026 | d13d0e83 blocker placed on researcher |
| 31 May 2026 | Researcher formally concluded Bugcrowd disclosure for 9e946ca3 |

---

## Note on Triage Pattern

Five of six submissions received N/A responses. The single submission that reached vendor review (d13d0e83) is the one with the most straightforward impact demonstration (credential → file download). The remaining five — which include wire-level pcap evidence, server-side daemon logs, and direct CVE precedent citations — were closed at triage level.

In the case of finding 1, the first Request for Response expired without any response. In the case of findings 2, 3, and 6, the triage responses do not address the specific evidence submitted. In no case was the triage closure technically reconciled with the attached evidence.

The security community is invited to review the individual writeups and form its own assessment.

---

## Responsible Disclosure

All findings were submitted to the HPE Networking Product Public Program on Bugcrowd prior to publication. The program has classified findings 1, 2, 3, and 6 as non-vulnerabilities. Findings 4 and 5 remain in active disclosure and are not published here.

---

*Vesqer / JM00NJ — netacoding.com — github.com/JM00NJ*
