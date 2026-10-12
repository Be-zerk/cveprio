# CVE prioritization report

Generated 2026-10-12T02:39:53+00:00 · mode **offline_demo** · cveprio 0.3.0 · organisation: Northbeam Logistics (fictional)

> OFFLINE DEMO MODE: data comes from recorded fixtures (see retrieval times), not live sources. Results may be out of date.
> Inventory and business context are FICTIONAL example data.
> This product uses the NVD API but is not endorsed or certified by the NVD.
> CVE records: CVE Program (cve.org). KEV: CISA Known Exploited Vulnerabilities catalogue (CC0). EPSS: FIRST.org Exploit Prediction Scoring System (https://www.first.org/epss).
> When used: Ubuntu CVE tracker (ubuntu.com/security, Canonical) and Red Hat Security Data (access.redhat.com, CC BY 4.0, © Red Hat).

| CVE | Decision | Severity score alone | Attack activity | Severity | Your exposure |
|---|---|---|---|---|---|
| CVE-2021-44228 | P1 | P1 | Being attacked: on CISA's list since 2021-12-10 | 10.0 out of 10 (critical) | web-portal-01 is internet-facing and high importance |
| CVE-2023-44487 | P1 | P2 | Being attacked: on CISA's list since 2023-10-10 | 7.5 out of 10 (high) | web-portal-01 is internet-facing and high importance |
| CVE-2024-6387 | P1 | P2 | Demo attack code exists (CISA) | 8.1 out of 10 (high) | bastion-01 is internet-facing and high importance |
| CVE-2023-38545 | P2 (provisional) | P1 | Demo attack code exists (CISA) | 9.8 out of 10 (critical) | dev-laptop-17: internet exposure and importance not recorded (+1 more system) |
| CVE-2022-22965 | Needs review (provisional) | P1 | Being attacked: on CISA's list since 2022-04-04 | 9.8 out of 10 (critical) | Unclear whether web-portal-01 is affected |
| CVE-2024-47176 | P3 | P3 | Demo attack code exists (CISA) | 5.3 out of 10 (medium) | print-srv-01 is protected by a declared control (not verified) |
| CVE-2024-3094 | Not affected | P1 | Attacks likely: 86.0% predicted chance in 30 days | 10.0 out of 10 (critical) | Not affected: your installed version is outside the affected range |
| CVE-2026-11415 | Cancelled CVE | – | – | – | – |
| CVE-2026-99001 | Not published yet | – | – | – | – |

## CVE-2021-44228 — P1: Act now: emergency change / out-of-band patching

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Official description (copied word for word; untrusted text) [CVE.desc]:* Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints — Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that t

**Decision:** Fix now (P1) · **Severity score alone would say:** P1

**In short:** Attackers are known to be using it: it is on CISA's list of actively attacked flaws (added 2021-12-10), and CISA rates exploitation as active. It affects web-portal-01 (log4j-core 2.14.1) — internet-facing, high importance. Also check legacy-billing-03: it may be affected too, but this could not be confirmed automatically.

### What is known (sourced facts)
- CVE status: Published (active) — assigned by apache; published 2021-12-10; last updated 2025-10-21 [CVE.state]
- Severity: 10.0 / 10 (Critical) — CVSS 3.1 score from CISA; 3 sources agree. Full breakdown in Severity score details. [CVE.cvss.1]
- Type of flaw: Improper Input Validation (+3 more) — CWE-20: Improper Input Validation; CWE-400: Uncontrolled Resource Consumption; CWE-502: Deserialization of Untrusted Data; CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection'). CWE = MITRE's Common Weakness Enumeration. [CVE.cwe, NVD.cwe]
- On the US government's list of actively attacked flaws (KEV): Yes — Listed in the CISA Known Exploited Vulnerabilities catalogue. [KEV]
- Known to be exploited by attackers: Yes — Attacks have been seen: it is listed in CISA's Known Exploited Vulnerabilities catalogue and CISA's SSVC assessment rates exploitation as active. [KEV, CVE.ssvc]
- Attack code reported to be public: Yes — CISA's SSVC assessment says proof-of-concept code exists; 11 references are tagged as exploit material. Whether that code exists, works or is reliable is NOT verified by this tool. [CVE.ssvc, NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, NVD.ref.11, NVD.ref.14, NVD.ref.15]
- CISA's rating: attacks have been seen — CISA SSVC decision points: Exploitation=active, Automatable=yes, Technical Impact=total; assessed 2025-02-04. [CVE.ssvc]
- Predicted chance of attacks in the next 30 days: >99.9% — EPSS 1.0000, higher than 100.0% of all scored CVEs, scored 2026-10-10 (FIRST EPSS model). Estimates exploitation activity, not difficulty or impact. [EPSS]
- web-portal-01: log4j-core 2.14.1 is affected — NVD: versions 2.13.0 up to (not including) 2.15.0 are affected. [NVD.cpe]

### What remains uncertain
- legacy-billing-03: Log4j 2.x (bundled by appliance vendor) needs a manual version check — The product name in your inventory does not exactly match any affected product in this CVE; a similar name is not proof you are affected. Apache's CVE record lists 'apache log4j2', which only resembles your 'log4j'. [CVE.affected.1]

### Why this priority (rule trace)
1. Starts at P1: it has been on CISA's list of actively attacked flaws since 2021-12-10 and CISA rates exploitation as active — rule: flaws that are known to be attacked always start at P1.
2. Stays at P1: web-portal-01 is internet-facing and of high importance — it is already at the highest level.
3. Also check legacy-billing-03 — whether it is affected could not be confirmed automatically.

### Action supported by the evidence
- Upgrade log4j-core on web-portal-01 — currently 2.14.1; sources indicate the fix is in version 2.15.0 or later. [NVD.ref.9, NVD.ref.10, NVD.ref.12]
- Check the exact version of Log4j on legacy-billing-03 — recorded as 2.x (bundled by appliance vendor); confirm the build and any platform condition, then re-run. See the applicability table for why it is unclear [CVE.affected.1].
- Follow CISA's official instructions for this flaw — quoted source text: For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available. [KEV]

### What would change the recommendation
- If a protection such as a firewall rule blocks access to web-portal-01 → Fix in the next patch cycle (P2) — a declared protection lowers the priority by one step
- Once web-portal-01 is upgraded and checked → no action needed — the fix is installed and confirmed

### AI-assisted assessment (judgement, not fact)

Status: `not_configured` — not_configured: no scripted example for CVE-2021-44228

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| web-portal-01 | log4j-core 2.14.1 | affected | [affected] NVD apache:log4j: in range ≥2.13.0 &lt;2.15.0 |
| legacy-billing-03 | Log4j 2.x (bundled by appliance vendor) | needs_review | No exact product match; similar product names found (similarity does not establish that this deployment is affected):; CNA:apache: similar name: 'log4j' vs 'apache log4j2' |

### Severity score details

| Source | CVSS version | Score | Rating | Evidence |
|---|---|---|---|---|
| CISA **(used)** | 3.1 | 10.0 | Critical | CVE.cvss.1 |
| NVD | 3.1 | 10.0 | Critical | NVD.cvss.1 |
| CISA (copy in NVD) | 3.1 | 10.0 | Critical | NVD.cvss.2 |
| NVD | 2.0 | 9.3 | High | NVD.cvss.3 |

What the 10.0 score says: Attack from: the network (remotely); Attack complexity: low — no special conditions; Login / privileges needed: none; A user must do something: no; Impact spreads beyond the component: yes; Impact on confidentiality (data theft): high; Impact on integrity (data tampering): high; Impact on availability (outage): high (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`)

### Evidence

| ID | Source | Summary | Retrieved | Published / updated | URL |
|---|---|---|---|---|---|
| CVE.state | cve_org (demo) | CVE record state PUBLISHED (assigner apache, data version 5.1). | 2026-10-10T21:13:11+00:00 | 2021-12-10T00:00:00.000Z / 2025-10-21T23:25:23.121Z | https://cveawg.mitre.org/api/cve/CVE-2021-44228 |
| CVE.desc | cve_org (demo) | CNA description of the vulnerability (verbatim, untrusted text). | 2026-10-10T21:13:11+00:00 | 2021-12-10T00:00:00.000Z / 2025-10-21T23:25:23.121Z | https://cveawg.mitre.org/api/cve/CVE-2021-44228 |
| CVE.cwe | cve_org (demo) | CNA weakness classification: CWE-20, CWE-400, CWE-502 | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2021-44228 |
| CVE.affected.1 | cve_org (demo) | CNA:apache lists affected product 'Apache Software Foundation / Apache Log4j2' with 1 version statement(s); default status unspecified. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2021-44228 |
| CVE.cvss.1 | cve_org (demo) | CVSS 3.1 base score 10 (CRITICAL) from ADP:CISA-ADP [adp] | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2021-44228 |
| CVE.ssvc | cve_org (demo) | CISA-ADP SSVC decision points: Exploitation=active, Automatable=yes, Technical Impact=total (assessed 2025-02-04T14:25:34.416117Z). | 2026-10-10T21:13:11+00:00 | - / 2025-02-04T14:25:34.416117Z | https://cveawg.mitre.org/api/cve/CVE-2021-44228 |
| NVD.status | nvd (demo) | NVD analysis status: Analyzed (last modified 2026-08-11T19:33:44.513). | 2026-10-10T21:13:11+00:00 | 2021-12-10T10:15:09.143 / 2026-08-11T19:33:44.513 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 |
| NVD.cvss.1 | nvd (demo) | CVSS 3.1 base score 10.0 (CRITICAL) from nvd@nist.gov [Primary] | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 |
| NVD.cvss.2 | nvd (demo) | CVSS 3.1 base score 10.0 (CRITICAL) from CISA-ADP (copy in NVD) [Secondary] | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 |
| NVD.cvss.3 | nvd (demo) | CVSS 2.0 base score 9.3 (HIGH) from nvd@nist.gov [Primary] | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 |
| NVD.cwe | nvd (demo) | NVD weakness classification: CWE-20, CWE-400, CWE-502, CWE-917 | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 |
| NVD.cpe | nvd (demo) | NVD lists 373 vulnerable CPE match criteria. | 2026-10-10T21:13:11+00:00 | - / 2026-08-11T19:33:44.513 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 |
| NVD.ref.1 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: http://packetstormsecurity.com/files/165261/Apache-Log4j2-2.14.1-Information-Disclosure.html |
| NVD.ref.2 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: http://packetstormsecurity.com/files/165270/Apache-Log4j2-2.14.1-Remote-Code-Execution.html |
| NVD.ref.3 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: http://packetstormsecurity.com/files/165371/VMware-Security-Advisory-2021-0028.4.html |
| NVD.ref.4 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: http://packetstormsecurity.com/files/165532/Log4Shell-HTTP-Header-Injection.html |
| NVD.ref.5 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: http://packetstormsecurity.com/files/165642/VMware-vCenter-Server-Unauthenticated-Log4Shell-JNDI-Injection-Remote-Code-Execution.html |
| NVD.ref.6 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: http://packetstormsecurity.com/files/165673/UniFi-Network-Application-Unauthenticated-Log4Shell-Remote-Code-Execution.html |
| NVD.ref.7 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: http://packetstormsecurity.com/files/167917/MobileIron-Log4Shell-Remote-Command-Execution.html |
| NVD.ref.8 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: http://seclists.org/fulldisclosure/2022/Dec/2 |
| NVD.ref.9 | nvd (demo) | NVD reference tagged Mailing List, Mitigation, Third Party Advisory. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: http://www.openwall.com/lists/oss-security/2021/12/10/1 |
| NVD.ref.10 | nvd (demo) | NVD reference tagged Mailing List, Mitigation, Third Party Advisory. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: http://www.openwall.com/lists/oss-security/2021/12/10/2 |
| NVD.ref.11 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-44228 |
| NVD.ref.12 | nvd (demo) | NVD reference tagged Release Notes, Vendor Advisory. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: https://logging.apache.org/log4j/2.x/security.html |
| NVD.ref.13 | nvd (demo) | NVD reference tagged Patch, Third Party Advisory, Vendor Advisory. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/ |
| NVD.ref.14 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: https://twitter.com/kurtseifried/status/1469345530182455296 |
| NVD.ref.15 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: https://www.nu11secur1ty.com/2021/12/cve-2021-44228.html |
| NVD.ref.16 | nvd (demo) | NVD reference tagged Patch, Third Party Advisory. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: https://www.oracle.com/security-alerts/cpuapr2022.html |
| NVD.ref.17 | nvd (demo) | NVD reference tagged Patch, Third Party Advisory. | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → ref: https://www.oracle.com/security-alerts/cpujan2022.html |
| UBUNTU | ubuntu (demo) | Ubuntu security tracker: status for 1 source package(s) across Ubuntu releases. | 2026-10-11T17:36:33+00:00 | 2021-12-10T00:00:00 / 2025-08-25T23:42:52.988006+00:00 | https://ubuntu.com/security/cves/CVE-2021-44228.json |
| KEV | cisa_kev (demo) | Listed in CISA KEV (added 2021-12-10; known ransomware use: Known; federal due date 2021-12-24). | 2026-10-10T21:14:10+00:00 | 2021-12-10 / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 1.0000 (percentile 1.0000) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:11+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2021-44228 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok; ubuntu=ok

## CVE-2023-44487 — P1: Act now: emergency change / out-of-band patching

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Official description (copied word for word; untrusted text) [CVE.desc]:* The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

**Decision:** Fix now (P1) · **Severity score alone would say:** P2

**In short:** Attackers are known to be using it: it is on CISA's list of actively attacked flaws (added 2023-10-10), and CISA rates exploitation as active. It affects web-portal-01 (nginx 1.25.2) — internet-facing, high importance.

### What is known (sourced facts)
- CVE status: Published (active) — assigned by mitre; published 2023-10-10; last updated 2026-07-14 [CVE.state]
- Severity: 7.5 / 10 (High) — CVSS 3.1 score from CISA; 3 sources agree. Full breakdown in Severity score details. [CVE.cvss.1]
- Type of flaw: Uncontrolled Resource Consumption — CWE-400: Uncontrolled Resource Consumption. CWE = MITRE's Common Weakness Enumeration. [NVD.cwe]
- On the US government's list of actively attacked flaws (KEV): Yes — Listed in the CISA Known Exploited Vulnerabilities catalogue. [KEV]
- Known to be exploited by attackers: Yes — Attacks have been seen: it is listed in CISA's Known Exploited Vulnerabilities catalogue and CISA's SSVC assessment rates exploitation as active. [KEV, CVE.ssvc]
- Attack code reported to be public: Yes — CISA's SSVC assessment says proof-of-concept code exists; 2 references are tagged as exploit material. Whether that code exists, works or is reliable is NOT verified by this tool. [CVE.ssvc, NVD.ref.11, NVD.ref.12]
- CISA's rating: attacks have been seen — CISA SSVC decision points: Exploitation=active, Automatable=yes, Technical Impact=partial; assessed 2024-07-23. [CVE.ssvc]
- Predicted chance of attacks in the next 30 days: >99.9% — EPSS 1.0000, higher than 100.0% of all scored CVEs, scored 2026-10-10 (FIRST EPSS model). Estimates exploitation activity, not difficulty or impact. [EPSS]
- web-portal-01: nginx 1.25.2 is affected — NVD: versions 1.9.5 up to and including 1.25.2 are affected. [NVD.cpe]

### What remains uncertain
- Nothing flagged.

### Why this priority (rule trace)
1. Starts at P1: it has been on CISA's list of actively attacked flaws since 2023-10-10 and CISA rates exploitation as active — rule: flaws that are known to be attacked always start at P1.
2. Stays at P1: web-portal-01 is internet-facing and of high importance — it is already at the highest level.

### Action supported by the evidence
- Upgrade nginx on web-portal-01 — currently 1.25.2; follow the vendor advisory for the fixed version. [NVD.ref.1, NVD.ref.2, NVD.ref.3]
- Follow CISA's official instructions for this flaw — quoted source text: Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable. [KEV]

### What would change the recommendation
- If a protection such as a firewall rule blocks access to web-portal-01 → Fix in the next patch cycle (P2) — a declared protection lowers the priority by one step
- Once web-portal-01 is upgraded and checked → no action needed — the fix is installed and confirmed

### AI-assisted assessment (judgement, not fact)

Status: `not_configured` — not_configured: no scripted example for CVE-2023-44487

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| web-portal-01 | nginx 1.25.2 | affected | [affected] NVD f5:nginx: in range ≥1.9.5 ≤1.25.2 |

### Severity score details

| Source | CVSS version | Score | Rating | Evidence |
|---|---|---|---|---|
| CISA **(used)** | 3.1 | 7.5 | High | CVE.cvss.1 |
| NVD | 3.1 | 7.5 | High | NVD.cvss.1 |
| CISA (copy in NVD) | 3.1 | 7.5 | High | NVD.cvss.2 |

What the 7.5 score says: Attack from: the network (remotely); Attack complexity: low — no special conditions; Login / privileges needed: none; A user must do something: no; Impact spreads beyond the component: no; Impact on confidentiality (data theft): none; Impact on integrity (data tampering): none; Impact on availability (outage): high (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)

### Evidence

| ID | Source | Summary | Retrieved | Published / updated | URL |
|---|---|---|---|---|---|
| CVE.state | cve_org (demo) | CVE record state PUBLISHED (assigner mitre, data version 5.2). | 2026-10-10T21:13:24+00:00 | 2023-10-10T00:00:00.000Z / 2026-07-14T12:03:17.389Z | https://cveawg.mitre.org/api/cve/CVE-2023-44487 |
| CVE.desc | cve_org (demo) | CNA description of the vulnerability (verbatim, untrusted text). | 2026-10-10T21:13:24+00:00 | 2023-10-10T00:00:00.000Z / 2026-07-14T12:03:17.389Z | https://cveawg.mitre.org/api/cve/CVE-2023-44487 |
| CVE.affected.1 | cve_org (demo) | CNA:mitre lists affected product 'n/a / n/a' with 1 version statement(s); default status unspecified. | 2026-10-10T21:13:24+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2023-44487 |
| CVE.cvss.1 | cve_org (demo) | CVSS 3.1 base score 7.5 (HIGH) from ADP:CISA-ADP [adp] | 2026-10-10T21:13:24+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2023-44487 |
| CVE.ssvc | cve_org (demo) | CISA-ADP SSVC decision points: Exploitation=active, Automatable=yes, Technical Impact=partial (assessed 2024-07-23T20:34:21.334116Z). | 2026-10-10T21:13:24+00:00 | - / 2024-07-23T20:34:21.334116Z | https://cveawg.mitre.org/api/cve/CVE-2023-44487 |
| CVE.affected.2 | cve_org (demo) | ADP:CISA-ADP lists affected product 'ietf / http' with 1 version statement(s); default status unknown. | 2026-10-10T21:13:24+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2023-44487 |
| NVD.status | nvd (demo) | NVD analysis status: Analyzed (last modified 2026-08-11T19:37:30.880). | 2026-10-10T21:13:30+00:00 | 2023-10-10T14:15:10.883 / 2026-08-11T19:37:30.880 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 |
| NVD.cvss.1 | nvd (demo) | CVSS 3.1 base score 7.5 (HIGH) from nvd@nist.gov [Primary] | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 |
| NVD.cvss.2 | nvd (demo) | CVSS 3.1 base score 7.5 (HIGH) from CISA-ADP (copy in NVD) [Secondary] | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 |
| NVD.cwe | nvd (demo) | NVD weakness classification: CWE-400 | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 |
| NVD.cpe | nvd (demo) | NVD lists 304 vulnerable CPE match criteria. | 2026-10-10T21:13:30+00:00 | - / 2026-08-11T19:37:30.880 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 |
| NVD.ref.1 | nvd (demo) | NVD reference tagged Vendor Advisory. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://access.redhat.com/security/cve/cve-2023-44487 |
| NVD.ref.2 | nvd (demo) | NVD reference tagged Technical Description, Vendor Advisory. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/ |
| NVD.ref.3 | nvd (demo) | NVD reference tagged Third Party Advisory, Vendor Advisory. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://blog.cloudflare.com/zero-day-rapid-reset-http2-record-breaking-ddos-attack/ |
| NVD.ref.4 | nvd (demo) | NVD reference tagged Vendor Advisory. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://blog.litespeedtech.com/2023/10/11/rapid-reset-http-2-vulnerablilty/ |
| NVD.ref.5 | nvd (demo) | NVD reference tagged Vendor Advisory. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://blog.vespa.ai/cve-2023-44487/ |
| NVD.ref.6 | nvd (demo) | NVD reference tagged Issue Tracking, Vendor Advisory. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://bugzilla.redhat.com/show_bug.cgi?id=2242803 |
| NVD.ref.7 | nvd (demo) | NVD reference tagged Issue Tracking, Vendor Advisory. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://bugzilla.suse.com/show_bug.cgi?id=1216123 |
| NVD.ref.8 | nvd (demo) | NVD reference tagged Mailing List, Patch, Vendor Advisory. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://cgit.freebsd.org/ports/commit/?id=c64c329c2c1752f46b73e3e6ce9f4329be6629f9 |
| NVD.ref.9 | nvd (demo) | NVD reference tagged Technical Description, Vendor Advisory. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://cloud.google.com/blog/products/identity-security/google-cloud-mitigated-largest-ddos-attack-peaking-above-398-million-rps/ |
| NVD.ref.10 | nvd (demo) | NVD reference tagged Technical Description, Vendor Advisory. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack |
| NVD.ref.11 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://github.com/micrictor/http2-rst-stream |
| NVD.ref.12 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 → ref: https://security.netapp.com/advisory/ntap-20240621-0006/ |
| UBUNTU | ubuntu (demo) | Ubuntu security tracker: status for 14 source package(s) across Ubuntu releases. | 2026-10-11T17:26:50+00:00 | 2023-10-10T00:00:00 / 2025-11-26T18:22:23.456963+00:00 | https://ubuntu.com/security/cves/CVE-2023-44487.json |
| KEV | cisa_kev (demo) | Listed in CISA KEV (added 2023-10-10; known ransomware use: Unknown; federal due date 2023-10-31). | 2026-10-10T21:14:10+00:00 | 2023-10-10 / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 1.0000 (percentile 1.0000) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:30+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2023-44487 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok; ubuntu=ok

## CVE-2024-6387 — P1: Act now: emergency change / out-of-band patching

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Official description (copied word for word; untrusted text) [CVE.desc]:* Openssh: regresshion - race condition in ssh allows rce/dos — A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

**Decision:** Fix now (P1) · **Severity score alone would say:** P2

**In short:** Attacks are likely: CISA says demo attack code exists; 9 public sources point to attack code; the predicted chance of attacks in the next 30 days is 99.5%. No confirmed attacks are on record. It affects bastion-01 (OpenSSH 9.6p1) — internet-facing, high importance.

### What is known (sourced facts)
- CVE status: Published (active) — assigned by redhat; published 2024-07-01; last updated 2026-09-01 [CVE.state]
- Severity: 8.1 / 10 (High) — CVSS 3.1 score from redhat, which published the CVE; 3 sources agree. Full breakdown in Severity score details. [CVE.cvss.1]
- Type of flaw: Signal Handler Race Condition (+1 more) — CWE-364: Signal Handler Race Condition; CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'). CWE = MITRE's Common Weakness Enumeration. [CVE.cwe, NVD.cwe]
- On the US government's list of actively attacked flaws (KEV): No — Not in KEV catalogue 2026.10.08 (absence is not evidence of no exploitation). [KEV]
- Attack code reported to be public: Yes — CISA's SSVC assessment says proof-of-concept code exists; 9 references are tagged as exploit material. Whether that code exists, works or is reliable is NOT verified by this tool. [CVE.ssvc, NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, NVD.ref.12, NVD.ref.13]
- CISA's rating: demo attack code exists — CISA SSVC decision points: Exploitation=poc, Automatable=no, Technical Impact=total; assessed 2024-07-02. [CVE.ssvc]
- Predicted chance of attacks in the next 30 days: 99.5% — EPSS 0.9951, higher than 99.9% of all scored CVEs, scored 2026-10-10 (FIRST EPSS model). Estimates exploitation activity, not difficulty or impact. [EPSS]
- bastion-01: OpenSSH 9.6p1 is affected — Red Hat's CVE record: versions 8.5p1 up to and including 9.7p1 are affected. NVD: versions 8.6 up to and including 9.8 are affected. [CVE.affected.1, NVD.cpe]
- ops-ubuntu-02: OpenSSH 1:9.6p1-3ubuntu13.4 is not affected — Ubuntu (noble): Ubuntu fixed openssh in 1:9.6p1-3ubuntu13.3; the installed 1:9.6p1-3ubuntu13.4 is that version or newer. Distribution builds are judged by the distribution's own advisory, not upstream version ranges. [UBUNTU]

### What remains uncertain
- Known to be exploited by attackers: Unknown — No positive evidence of in-the-wild exploitation in the sources checked. This is not proof that exploitation has not occurred. [KEV, CVE.ssvc]
- Some evidence may be out of date — SSVC Exploitation=poc was assessed 2024-07-02 (> 180 days ago) and may no longer reflect current activity. [CVE.ssvc]
- Demo data: the attacked-flaws list (KEV) is a reduced copy — Offline demo uses a trimmed KEV fixture; absence was verified against the full catalogue at capture time only.
- Scripted AI example asks: Which builds and architectures do the public PoCs target, and how… — Which builds and architectures do the public PoCs target, and how many attempts do they need? (Source: scripted demo example; not verified.)
- Scripted AI example asks: Has in-the-wild exploitation been reported since the SSVC assessment… — Has in-the-wild exploitation been reported since the SSVC assessment date? (Source: scripted demo example; not verified.)
- Little public research doesn't mean it's hard to exploit — Exploit-development difficulty judged from public evidence is inherently limited: the absence of public research does not mean exploitation is hard.

### Why this priority (rule trace)
1. Starts at P2: CISA says demo attack code exists — rule: a CISA proof-of-concept rating, a predicted chance of attacks of 10% or more, or a validated AI rating of 'easy to exploit' each start at P2.
2. Raised to P1: bastion-01 is internet-facing and of high importance — rule: internet-facing systems, and systems of high or critical importance, move the priority up one step.

### Action supported by the evidence
- Upgrade OpenSSH on bastion-01 — currently 9.6p1; follow the vendor advisory for the fixed version. [NVD.ref.4, NVD.ref.9, NVD.ref.10]

### What would change the recommendation
- If a protection such as a firewall rule blocks access to bastion-01 → Schedule a fix (P3) — a declared protection lowers the priority by one step
- Once bastion-01 is upgraded and checked → no action needed — the fix is installed and confirmed
- If the sources' disagreements are resolved → the decision may change — see 'What's uncertain' for which sources disagree.

### AI-assisted assessment (judgement, not fact)

> **SCRIPTED EXAMPLE** — hand-written by the project author to demonstrate validation in the offline demo. It was NOT produced by a language model.

Provider `scripted`, model `scripted-example`, prompt version 2026-10-11.1. 6 of 9 claims passed the checks (cited evidence exists, the quote appears in it word for word, numbers and dates match). That shows grounding, not that the reasoning is right. Ratings are opinions, not probabilities.

**Exploit-development difficulty:** `moderate`
- *Prerequisites:* The attacker needs only network access to sshd and no credentials; the trigger is failing to authenticate within the login time limit. (fact) [CVE.desc, CVE.cvss.1] — quote: “An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period”
- *Complexity:* The flaw is a race condition in signal handling, and the CNA scores attack complexity as High, which suggests exploitation depends on winning a timing window. (inference) [CVE.desc, CVE.cvss.1] — quote: “There is a race condition which can lead sshd to handle some signals in an unsafe manner”
- *Research availability:* Several references tagged 'Exploit' by NVD, including a researcher advisory, indicate detailed public research exists. (fact) [NVD.ref.2, NVD.ref.12] — quote: “NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist”

**Existing-exploit usability:** `public_exploit_claimed`
- *Exploit evidence:* CISA's SSVC assessment records Exploitation=poc. (fact) [CVE.ssvc] — quote: “SSVC decision points: Exploitation=poc”
- *Reliability limits:* A race-condition exploit is likely to need many connection attempts, which may be visible in authentication logs. (inference) [CVE.desc, CVE.cvss.1] — quote: “There is a race condition which can lead sshd to handle some signals”
- *Required access:* Network reachability to the SSH service; no privileges or user interaction. (fact) [CVE.desc, CVE.cvss.1] — quote: “An unauthenticated, remote attacker may be able to trigger it”

*Scripted summary (uncited free text):* Unauthenticated remote race condition in sshd with public research and PoC claims; timing complexity is the main barrier.

**Validation removed/overrode:**
- `difficulty.complexity_factors[1]`: cites unknown evidence ID(s): ['NVD.ref.99'] — “Exploitation is reliable on all Linux distributions.”
- `difficulty.complexity_factors[2]`: its quote does not appear in the cited evidence — “Public exploits succeed in under a minute on default installations.”
- `difficulty.research_availability[1]`: no evidence cited — “Public write-ups make weaponisation trivial.”
- `usability.rating`: rating 'exploitation_reported' → 'public_exploit_claimed': no source in the bundle reports in-the-wild exploitation

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| bastion-01 | OpenSSH 9.6p1 | affected | [affected] CNA:redhat 'OpenSSH': name 'openssh': in range 8.5p1..≤9.7p1 → affected; [affected] NVD openbsd:openssh: in range ≥8.6 ≤9.8 |
| ops-ubuntu-02 | OpenSSH 1:9.6p1-3ubuntu13.4 | not_affected | [not_affected] Ubuntu (noble): Ubuntu fixed openssh in 1:9.6p1-3ubuntu13.3; the installed 1:9.6p1-3ubuntu13.4 is that version or newer; Distribution builds are judged by the distribution's own advisory, not upstream version ranges. |

### Severity score details

| Source | CVSS version | Score | Rating | Evidence |
|---|---|---|---|---|
| redhat, which published the CVE **(used)** | 3.1 | 8.1 | High | CVE.cvss.1 |
| redhat.com | 3.1 | 8.1 | High | NVD.cvss.1 |
| NVD | 3.1 | 8.1 | High | NVD.cvss.2 |

What the 8.1 score says: Attack from: the network (remotely); Attack complexity: high — needs special conditions or timing; Login / privileges needed: none; A user must do something: no; Impact spreads beyond the component: no; Impact on confidentiality (data theft): high; Impact on integrity (data tampering): high; Impact on availability (outage): high (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`)

### Evidence

| ID | Source | Summary | Retrieved | Published / updated | URL |
|---|---|---|---|---|---|
| CVE.state | cve_org (demo) | CVE record state PUBLISHED (assigner redhat, data version 5.2). | 2026-10-10T21:13:11+00:00 | 2024-07-01T12:37:25.431Z / 2026-09-01T11:07:10.385Z | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.desc | cve_org (demo) | CNA description of the vulnerability (verbatim, untrusted text). | 2026-10-10T21:13:11+00:00 | 2024-07-01T12:37:25.431Z / 2026-09-01T11:07:10.385Z | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.cwe | cve_org (demo) | CNA weakness classification: CWE-364 | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.cvss.1 | cve_org (demo) | CVSS 3.1 base score 8.1 (HIGH) from CNA:redhat [cna] | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.1 | cve_org (demo) | CNA:redhat lists affected product '- / OpenSSH' with 1 version statement(s); default status unaffected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.2 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 9' with 1 version statement(s); default status affected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.3 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 9' with 1 version statement(s); default status affected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.4 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 9.0 Update Services for SAP Solutions' with 1 version statement(s); default status affected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.5 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 9.2 Extended Update Support' with 1 version statement(s); default status affected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.6 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat OpenShift Container Platform 4.13' with 1 version statement(s); default status affected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.7 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat OpenShift Container Platform 4.14' with 1 version statement(s); default status affected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.8 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat OpenShift Container Platform 4.15' with 1 version statement(s); default status affected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.9 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat OpenShift Container Platform 4.16' with 1 version statement(s); default status affected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.10 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Ceph Storage 5' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.11 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Ceph Storage 6' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.12 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Ceph Storage 7' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.13 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 10' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.14 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 6' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.15 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 7' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.16 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 8' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.affected.17 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat OpenShift Container Platform 4' with 0 version statement(s); default status affected. | 2026-10-10T21:13:11+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| CVE.ssvc | cve_org (demo) | CISA-ADP SSVC decision points: Exploitation=poc, Automatable=no, Technical Impact=total (assessed 2024-07-02T13:18:34.695298Z). | 2026-10-10T21:13:11+00:00 | - / 2024-07-02T13:18:34.695298Z | https://cveawg.mitre.org/api/cve/CVE-2024-6387 |
| NVD.status | nvd (demo) | NVD analysis status: Modified (last modified 2026-09-01T12:17:13.423). | 2026-10-10T21:13:17+00:00 | 2024-07-01T13:15:06.467 / 2026-09-01T12:17:13.423 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 |
| NVD.cvss.1 | nvd (demo) | CVSS 3.1 base score 8.1 (HIGH) from secalert@redhat.com [Secondary] | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 |
| NVD.cvss.2 | nvd (demo) | CVSS 3.1 base score 8.1 (HIGH) from nvd@nist.gov [Primary] | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 |
| NVD.cwe | nvd (demo) | NVD weakness classification: CWE-362, CWE-364 | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 |
| NVD.cpe | nvd (demo) | NVD lists 92 vulnerable CPE match criteria. | 2026-10-10T21:13:17+00:00 | - / 2026-09-01T12:17:13.423 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 |
| NVD.ref.1 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: https://santandersecurityresearch.github.io/blog/sshing_the_masses.html |
| NVD.ref.2 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt |
| NVD.ref.3 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: http://www.openwall.com/lists/oss-security/2024/07/03/11 |
| NVD.ref.4 | nvd (demo) | NVD reference tagged Mailing List, Patch. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: http://www.openwall.com/lists/oss-security/2024/07/03/3 |
| NVD.ref.5 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: http://www.openwall.com/lists/oss-security/2024/07/04/2 |
| NVD.ref.6 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: http://www.openwall.com/lists/oss-security/2024/07/08/2 |
| NVD.ref.7 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: http://www.openwall.com/lists/oss-security/2024/07/09/5 |
| NVD.ref.8 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: http://www.openwall.com/lists/oss-security/2024/07/10/1 |
| NVD.ref.9 | nvd (demo) | NVD reference tagged Patch. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: https://github.com/openela-main/openssh/commit/e1f438970e5a337a17070a637c1b9e19697cad09 |
| NVD.ref.10 | nvd (demo) | NVD reference tagged Mailing List, Patch. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: https://lists.mindrot.org/pipermail/openssh-unix-dev/2024-July/041431.html |
| NVD.ref.11 | nvd (demo) | NVD reference tagged Issue Tracking, Patch. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: https://news.ycombinator.com/item?id=40843778 |
| NVD.ref.12 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: https://www.exploit-db.com/exploits/52269 |
| NVD.ref.13 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:17+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387 → ref: https://www.vicarius.io/vsociety/posts/regresshion-an-openssh-regression-error-cve-2024-6387 |
| UBUNTU | ubuntu (demo) | Ubuntu security tracker: status for 2 source package(s) across Ubuntu releases. | 2026-10-11T17:27:15+00:00 | 2024-07-01T00:00:00 / 2025-08-26T10:54:32.557876+00:00 | https://ubuntu.com/security/cves/CVE-2024-6387.json |
| KEV | cisa_kev (demo) | Not listed in CISA KEV catalogue version 2026.10.08. Absence does NOT show the vulnerability is unexploited — only that CISA has not added it. | 2026-10-10T21:14:10+00:00 | 2026-10-08T20:09:18.9833Z / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 0.9951 (percentile 0.9994) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:17+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2024-6387 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok; ubuntu=ok

## CVE-2023-38545 — P2: Next patch cycle, ahead of routine work (provisional)

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Official description (copied word for word; untrusted text) [CVE.desc]:* This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake.  When curl is asked to pass along the host name to the SOCKS5 proxy to allow that to resolve the address instead of it getting done by curl itself, the maximum length that host name can be is 255 bytes.  If the host name is detected to be longer, curl switches to local name resolving and instead passes on the resolved address only. Due to this bug, the local variable that means "let the host resolve the name" could get the wrong value during a slow SOCKS5 handshake, and contrary to the intention, copy the too long host name to the target buffer instead of copying just the resolved address there.  The target buff

**Decision:** Fix in the next patch cycle (P2) — provisional, depends on information not supplied · **Severity score alone would say:** P1

**In short:** Attacks are likely: CISA says demo attack code exists; the predicted chance of attacks in the next 30 days is 78.5%. No confirmed attacks are on record. It affects ops-ubuntu-02 (curl 8.3.0) — internal, medium importance; dev-laptop-17 (curl 8.3.0) — internet exposure and importance not recorded.

### What is known (sourced facts)
- CVE status: Published (active) — assigned by hackerone; published 2023-10-18; last updated 2026-07-14 [CVE.state]
- Severity: 9.8 / 10 (Critical) — CVSS 3.1 score from NVD; the highest of 2 different scores from 3 sources (see What's uncertain). Full breakdown in Severity score details. [NVD.cvss.1]
- Type of flaw: Out-of-bounds Write — CWE-787: Out-of-bounds Write. CWE = MITRE's Common Weakness Enumeration. [NVD.cwe]
- On the US government's list of actively attacked flaws (KEV): No — Not in KEV catalogue 2026.10.08 (absence is not evidence of no exploitation). [KEV]
- Attack code reported to be public: Yes — CISA's SSVC assessment says proof-of-concept code exists. Whether that code exists, works or is reliable is NOT verified by this tool. [CVE.ssvc]
- CISA's rating: demo attack code exists — CISA SSVC decision points: Exploitation=poc, Automatable=no, Technical Impact=total; assessed 2024-10-17. [CVE.ssvc]
- Predicted chance of attacks in the next 30 days: 78.5% — EPSS 0.7848, higher than 99.6% of all scored CVEs, scored 2026-10-10 (FIRST EPSS model). Estimates exploitation activity, not difficulty or impact. [EPSS]
- ops-ubuntu-02: curl 8.3.0 is affected — NVD: versions 7.69.0 up to (not including) 8.4.0 are affected. [NVD.cpe]
- dev-laptop-17: curl 8.3.0 is affected — NVD: versions 7.69.0 up to (not including) 8.4.0 are affected. [NVD.cpe]

### What remains uncertain
- Known to be exploited by attackers: Unknown — No positive evidence of in-the-wild exploitation in the sources checked. This is not proof that exploitation has not occurred. [KEV, CVE.ssvc]
- Sources give different severity scores — Sources disagree on CVSS 3.1 base score: CISA 8.8; NVD 9.8; CISA (copy in NVD) 8.8. Rules use the most severe value; verify against the vendor advisory. [CVE.cvss.1, NVD.cvss.1, NVD.cvss.2]
- Some evidence may be out of date — SSVC Exploitation=poc was assessed 2024-10-17 (> 180 days ago) and may no longer reflect current activity. [CVE.ssvc]
- Demo data: the attacked-flaws list (KEV) is a reduced copy — Offline demo uses a trimmed KEV fixture; absence was verified against the full catalogue at capture time only.
- Little public research doesn't mean it's hard to exploit — Exploit-development difficulty judged from public evidence is inherently limited: the absence of public research does not mean exploitation is hard.

### Why this priority (rule trace)
1. Starts at P2: CISA says demo attack code exists — rule: a CISA proof-of-concept rating, a predicted chance of attacks of 10% or more, or a validated AI rating of 'easy to exploit' each start at P2.
2. Stays the same for now: dev-laptop-17's internet exposure and importance are not recorded — the result is marked provisional instead of guessing the missing details.

### Action supported by the evidence
- Upgrade curl on ops-ubuntu-02 — currently 8.3.0; sources indicate the fix is in version 8.4.0 or later. [NVD.ref.1, NVD.ref.2]
- Upgrade curl on dev-laptop-17 — currently 8.3.0; sources indicate the fix is in version 8.4.0 or later. [NVD.ref.1, NVD.ref.2]

### What would change the recommendation
- If attackers are reported using it → Fix now (P1) — for example, if CISA adds it to its list of actively attacked flaws
- If dev-laptop-17 is internet-facing → Fix now (P1) — recording it as high or critical importance would have the same effect
- If the sources' disagreements are resolved → the decision may change — see 'What's uncertain' for which sources disagree.

### AI-assisted assessment (judgement, not fact)

Status: `not_configured` — not_configured: no scripted example for CVE-2023-38545

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| ops-ubuntu-02 | curl 8.3.0 | affected | [affected] NVD haxx:libcurl: in range ≥7.69.0 &lt;8.4.0 |
| dev-laptop-17 | curl 8.3.0 | affected | [affected] NVD haxx:libcurl: in range ≥7.69.0 &lt;8.4.0 |

### Severity score details

| Source | CVSS version | Score | Rating | Evidence |
|---|---|---|---|---|
| CISA | 3.1 | 8.8 | High | CVE.cvss.1 |
| NVD **(used)** | 3.1 | 9.8 | Critical | NVD.cvss.1 |
| CISA (copy in NVD) | 3.1 | 8.8 | High | NVD.cvss.2 |

What the 9.8 score says: Attack from: the network (remotely); Attack complexity: low — no special conditions; Login / privileges needed: none; A user must do something: no; Impact spreads beyond the component: no; Impact on confidentiality (data theft): high; Impact on integrity (data tampering): high; Impact on availability (outage): high (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)

### Evidence

| ID | Source | Summary | Retrieved | Published / updated | URL |
|---|---|---|---|---|---|
| CVE.state | cve_org (demo) | CVE record state PUBLISHED (assigner hackerone, data version 5.2). | 2026-10-10T21:13:31+00:00 | 2023-10-18T03:52:00.816Z / 2026-07-14T12:03:14.064Z | https://cveawg.mitre.org/api/cve/CVE-2023-38545 |
| CVE.desc | cve_org (demo) | CNA description of the vulnerability (verbatim, untrusted text). | 2026-10-10T21:13:31+00:00 | 2023-10-18T03:52:00.816Z / 2026-07-14T12:03:14.064Z | https://cveawg.mitre.org/api/cve/CVE-2023-38545 |
| CVE.affected.1 | cve_org (demo) | CNA:hackerone lists affected product 'curl / curl' with 2 version statement(s); default status unspecified. | 2026-10-10T21:13:31+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2023-38545 |
| CVE.cvss.1 | cve_org (demo) | CVSS 3.1 base score 8.8 (HIGH) from ADP:CISA-ADP [adp] | 2026-10-10T21:13:31+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2023-38545 |
| CVE.ssvc | cve_org (demo) | CISA-ADP SSVC decision points: Exploitation=poc, Automatable=no, Technical Impact=total (assessed 2024-10-17T21:11:03.346985Z). | 2026-10-10T21:13:31+00:00 | - / 2024-10-17T21:11:03.346985Z | https://cveawg.mitre.org/api/cve/CVE-2023-38545 |
| NVD.status | nvd (demo) | NVD analysis status: Modified (last modified 2026-06-17T06:10:41.627). | 2026-10-10T21:13:37+00:00 | 2023-10-18T04:15:11.077 / 2026-06-17T06:10:41.627 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 |
| NVD.cvss.1 | nvd (demo) | CVSS 3.1 base score 9.8 (CRITICAL) from nvd@nist.gov [Primary] | 2026-10-10T21:13:37+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 |
| NVD.cvss.2 | nvd (demo) | CVSS 3.1 base score 8.8 (HIGH) from CISA-ADP (copy in NVD) [Secondary] | 2026-10-10T21:13:37+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 |
| NVD.cwe | nvd (demo) | NVD weakness classification: CWE-787 | 2026-10-10T21:13:37+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 |
| NVD.cpe | nvd (demo) | NVD lists 14 vulnerable CPE match criteria. | 2026-10-10T21:13:37+00:00 | - / 2026-06-17T06:10:41.627 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 |
| NVD.ref.1 | nvd (demo) | NVD reference tagged Patch, Third Party Advisory. | 2026-10-10T21:13:37+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 → ref: https://curl.se/docs/CVE-2023-38545.html |
| NVD.ref.2 | nvd (demo) | NVD reference tagged Patch, Third Party Advisory. | 2026-10-10T21:13:37+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 → ref: https://www.secpod.com/blog/high-severity-heap-buffer-overflow-vulnerability/ |
| UBUNTU | ubuntu (demo) | Ubuntu security tracker: status for 1 source package(s) across Ubuntu releases. | 2026-10-11T17:27:41+00:00 | 2023-10-11T06:00:00 / 2025-08-04T19:47:04.684486+00:00 | https://ubuntu.com/security/cves/CVE-2023-38545.json |
| KEV | cisa_kev (demo) | Not listed in CISA KEV catalogue version 2026.10.08. Absence does NOT show the vulnerability is unexploited — only that CISA has not added it. | 2026-10-10T21:14:10+00:00 | 2026-10-08T20:09:18.9833Z / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 0.7848 (percentile 0.9958) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:37+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2023-38545 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok; ubuntu=ok

## CVE-2022-22965 — Needs version review (would be P1 if affected)

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Official description (copied word for word; untrusted text) [CVE.desc]:* A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

**Decision:** Needs review (would be P1 if affected) — provisional, depends on information not supplied · **Severity score alone would say:** P1

**In short:** Attackers are known to be using it: it is on CISA's list of actively attacked flaws (added 2022-04-04), and CISA rates exploitation as active. It is unclear whether web-portal-01's Spring Framework 5.3.17 is affected: its version is in the affected range, but the flaw only applies together with Oracle JDK, which your inventory does not record.

### What is known (sourced facts)
- CVE status: Published (active) — assigned by vmware; published 2022-04-01; last updated 2025-10-21 [CVE.state]
- Severity: 9.8 / 10 (Critical) — CVSS 3.1 score from CISA; 3 sources agree. Full breakdown in Severity score details. [CVE.cvss.1]
- Type of flaw: Code Injection — CWE-94: Improper Control of Generation of Code ('Code Injection'). CWE = MITRE's Common Weakness Enumeration. [CVE.cwe, NVD.cwe]
- On the US government's list of actively attacked flaws (KEV): Yes — Listed in the CISA Known Exploited Vulnerabilities catalogue. [KEV]
- Known to be exploited by attackers: Yes — Attacks have been seen: it is listed in CISA's Known Exploited Vulnerabilities catalogue and CISA's SSVC assessment rates exploitation as active. [KEV, CVE.ssvc]
- Attack code reported to be public: Yes — CISA's SSVC assessment says proof-of-concept code exists; 1 reference is tagged as exploit material. Whether that code exists, works or is reliable is NOT verified by this tool. [CVE.ssvc, NVD.ref.1]
- CISA's rating: attacks have been seen — CISA SSVC decision points: Exploitation=active, Automatable=yes, Technical Impact=total; assessed 2025-01-29. [CVE.ssvc]
- Predicted chance of attacks in the next 30 days: 99.6% — EPSS 0.9964, higher than 99.9% of all scored CVEs, scored 2026-10-10 (FIRST EPSS model). Estimates exploitation activity, not difficulty or impact. [EPSS]

### What remains uncertain
- web-portal-01: Spring Framework 5.3.17 needs a manual version check — VMware's CVE record: version statement 'Spring Framework versions 5.3.X prior to 5.3.18+, 5.2.x prior to 5.2.20+ and all' is not machine-comparable. NVD: versions 5.3.0 up to (not including) 5.3.18 are affected, but only together with Oracle JDK. [CVE.affected.1, NVD.cpe]

### Why this priority (rule trace)
1. Starts at P1: it has been on CISA's list of actively attacked flaws since 2022-04-04 and CISA rates exploitation as active — rule: flaws that are known to be attacked always start at P1.
2. Needs review: it is unclear whether web-portal-01's Spring Framework 5.3.17 is affected — it would be P1 if it is.

### Action supported by the evidence
- Check the exact version of Spring Framework on web-portal-01 — recorded as 5.3.17; confirm the build and any platform condition, then re-run. See the applicability table for why it is unclear [CVE.affected.1, NVD.cpe].
- Follow CISA's official instructions for this flaw — quoted source text: Apply updates per vendor instructions. [KEV]

### What would change the recommendation
- If web-portal-01's Spring Framework 5.3.17 turns out to be affected → Fix now (P1) — how exposed or important the system is would not change this
- If web-portal-01's Spring Framework 5.3.17 turns out not to be affected → no action needed — check the exact build and any platform condition

### AI-assisted assessment (judgement, not fact)

Status: `not_configured` — not_configured: no scripted example for CVE-2022-22965

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| web-portal-01 | Spring Framework 5.3.17 | needs_review | [ambiguous] CNA:vmware 'Spring Framework': name 'spring framework': version statement 'Spring Framework versions 5.3.X prior to 5.3.18+, 5.2.x prior to 5.2.20+ and all' is not machine-comparable; [ambiguous] NVD vmware:spring_framework: in range ≥5.3.0 &lt;5.3.18; NVD applies this only in combination with cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:* (AND configuration) — confirm that platform condition for this deployment |

### Severity score details

| Source | CVSS version | Score | Rating | Evidence |
|---|---|---|---|---|
| CISA **(used)** | 3.1 | 9.8 | Critical | CVE.cvss.1 |
| NVD | 3.1 | 9.8 | Critical | NVD.cvss.1 |
| CISA (copy in NVD) | 3.1 | 9.8 | Critical | NVD.cvss.2 |
| NVD | 2.0 | 7.5 | High | NVD.cvss.3 |

What the 9.8 score says: Attack from: the network (remotely); Attack complexity: low — no special conditions; Login / privileges needed: none; A user must do something: no; Impact spreads beyond the component: no; Impact on confidentiality (data theft): high; Impact on integrity (data tampering): high; Impact on availability (outage): high (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)

### Evidence

| ID | Source | Summary | Retrieved | Published / updated | URL |
|---|---|---|---|---|---|
| CVE.state | cve_org (demo) | CVE record state PUBLISHED (assigner vmware, data version 5.1). | 2026-10-10T21:13:44+00:00 | 2022-04-01T22:17:30.000Z / 2025-10-21T23:15:42.792Z | https://cveawg.mitre.org/api/cve/CVE-2022-22965 |
| CVE.desc | cve_org (demo) | CNA description of the vulnerability (verbatim, untrusted text). | 2026-10-10T21:13:44+00:00 | 2022-04-01T22:17:30.000Z / 2025-10-21T23:15:42.792Z | https://cveawg.mitre.org/api/cve/CVE-2022-22965 |
| CVE.cwe | cve_org (demo) | CNA weakness classification: CWE-94 | 2026-10-10T21:13:44+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2022-22965 |
| CVE.affected.1 | cve_org (demo) | CNA:vmware lists affected product 'n/a / Spring Framework' with 1 version statement(s); default status unspecified. | 2026-10-10T21:13:44+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2022-22965 |
| CVE.cvss.1 | cve_org (demo) | CVSS 3.1 base score 9.8 (CRITICAL) from ADP:CISA-ADP [adp] | 2026-10-10T21:13:44+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2022-22965 |
| CVE.ssvc | cve_org (demo) | CISA-ADP SSVC decision points: Exploitation=active, Automatable=yes, Technical Impact=total (assessed 2025-01-29T17:52:10.886552Z). | 2026-10-10T21:13:44+00:00 | - / 2025-01-29T17:52:10.886552Z | https://cveawg.mitre.org/api/cve/CVE-2022-22965 |
| NVD.status | nvd (demo) | NVD analysis status: Analyzed (last modified 2026-06-17T04:29:15.610). | 2026-10-10T21:13:50+00:00 | 2022-04-01T23:15:13.870 / 2026-06-17T04:29:15.610 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 |
| NVD.cvss.1 | nvd (demo) | CVSS 3.1 base score 9.8 (CRITICAL) from nvd@nist.gov [Primary] | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 |
| NVD.cvss.2 | nvd (demo) | CVSS 3.1 base score 9.8 (CRITICAL) from CISA-ADP (copy in NVD) [Secondary] | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 |
| NVD.cvss.3 | nvd (demo) | CVSS 2.0 base score 7.5 (HIGH) from nvd@nist.gov [Primary] | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 |
| NVD.cwe | nvd (demo) | NVD weakness classification: CWE-94 | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 |
| NVD.cpe | nvd (demo) | NVD lists 97 vulnerable CPE match criteria. | 2026-10-10T21:13:50+00:00 | - / 2026-06-17T04:29:15.610 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 |
| NVD.ref.1 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 → ref: http://packetstormsecurity.com/files/166713/Spring4Shell-Code-Execution.html |
| NVD.ref.2 | nvd (demo) | NVD reference tagged Patch, Third Party Advisory. | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 → ref: https://cert-portal.siemens.com/productcert/pdf/ssa-254054.pdf |
| NVD.ref.3 | nvd (demo) | NVD reference tagged Mitigation, Vendor Advisory. | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 → ref: https://tanzu.vmware.com/security/cve-2022-22965 |
| NVD.ref.4 | nvd (demo) | NVD reference tagged Patch, Third Party Advisory. | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 → ref: https://www.oracle.com/security-alerts/cpujul2022.html |
| UBUNTU | ubuntu (demo) | Ubuntu security tracker: status for 1 source package(s) across Ubuntu releases. | 2026-10-11T17:26:32+00:00 | 2022-04-01T00:00:00 / 2025-06-24T14:57:18.899115+00:00 | https://ubuntu.com/security/cves/CVE-2022-22965.json |
| KEV | cisa_kev (demo) | Listed in CISA KEV (added 2022-04-04; known ransomware use: Unknown; federal due date 2022-04-25). | 2026-10-10T21:14:10+00:00 | 2022-04-04 / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 0.9964 (percentile 0.9995) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:50+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2022-22965 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok; ubuntu=ok

## CVE-2024-47176 — P3: Scheduled remediation in normal maintenance

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Official description (copied word for word; untrusted text) [CVE.desc]:* cups-browsed binds to `INADDR_ANY:631`, trusting any packet from any source — CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL. When combined with other vulnerabilities, such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker can execute arbitrary commands remotely on the target machine without authentication when a malicious printer is printed to.

**Decision:** Schedule a fix (P3) · **Severity score alone would say:** P3

**In short:** Attacks are likely: CISA says demo attack code exists; 2 public sources point to attack code; the predicted chance of attacks in the next 30 days is 50.6%. No confirmed attacks are on record. It affects print-srv-01 (cups-browsed 2.0.1) — internal, low importance; protected by: Host firewall drops inbound traffic to port 631 except from the warehouse printer VLAN (not checked by this tool).

### What is known (sourced facts)
- CVE status: Published (active) — assigned by GitHub_M; published 2024-09-26; last updated 2025-11-04 [CVE.state]
- Severity: 5.3 / 10 (Medium) — CVSS 3.1 score from GitHub_M, which published the CVE; 2 sources agree. Full breakdown in Severity score details. [CVE.cvss.1]
- Type of flaw: Binding to an Unrestricted IP Address — CWE-1327: Binding to an Unrestricted IP Address. CWE = MITRE's Common Weakness Enumeration. [CVE.cwe, NVD.cwe]
- On the US government's list of actively attacked flaws (KEV): No — Not in KEV catalogue 2026.10.08 (absence is not evidence of no exploitation). [KEV]
- Attack code reported to be public: Yes — CISA's SSVC assessment says proof-of-concept code exists; 2 references are tagged as exploit material. Whether that code exists, works or is reliable is NOT verified by this tool. [CVE.ssvc, NVD.ref.1, NVD.ref.2]
- CISA's rating: demo attack code exists — CISA SSVC decision points: Exploitation=poc, Automatable=no, Technical Impact=partial; assessed 2024-09-27. [CVE.ssvc]
- Predicted chance of attacks in the next 30 days: 50.6% — EPSS 0.5060, higher than 98.9% of all scored CVEs, scored 2026-10-10 (FIRST EPSS model). Estimates exploitation activity, not difficulty or impact. [EPSS]
- print-srv-01: cups-browsed 2.0.1 is affected — GitHub's CVE record: the record says '<= 2.0.1', which includes your version. [CVE.affected.1]

### What remains uncertain
- Known to be exploited by attackers: Unknown — No positive evidence of in-the-wild exploitation in the sources checked. This is not proof that exploitation has not occurred. [KEV, CVE.ssvc]
- Some evidence may be out of date — SSVC Exploitation=poc was assessed 2024-09-27 (> 180 days ago) and may no longer reflect current activity. [CVE.ssvc]
- Demo data: the attacked-flaws list (KEV) is a reduced copy — Offline demo uses a trimmed KEV fixture; absence was verified against the full catalogue at capture time only.
- Scripted AI example asks: The bundle does not describe the other chained CVEs, so the… — The bundle does not describe the other chained CVEs, so the difficulty of the full chain cannot be assessed from this evidence. (Source: scripted demo example; not verified.)
- Little public research doesn't mean it's hard to exploit — Exploit-development difficulty judged from public evidence is inherently limited: the absence of public research does not mean exploitation is hard.

### Why this priority (rule trace)
1. Starts at P2: CISA says demo attack code exists — rule: a CISA proof-of-concept rating, a predicted chance of attacks of 10% or more, or a validated AI rating of 'easy to exploit' each start at P2.
2. Lowered to P3: print-srv-01 has a declared protection (Host firewall drops inbound traffic to port 631 except from the warehouse printer VLAN) — rule: a declared protection moves the priority down one step. The tool does not verify it.

### Action supported by the evidence
- Upgrade cups-browsed on print-srv-01 — currently 2.0.1; follow the vendor advisory for the fixed version. [NVD.ref.3]
- Confirm the protection on print-srv-01 is really in place until patched — Host firewall drops inbound traffic to port 631 except from the warehouse printer VLAN.

### What would change the recommendation
- If attackers are reported using it → Fix in the next patch cycle (P2) — for example, if CISA adds it to its list of actively attacked flaws
- If the sources' disagreements are resolved → the decision may change — see 'What's uncertain' for which sources disagree.

### AI-assisted assessment (judgement, not fact)

> **SCRIPTED EXAMPLE** — hand-written by the project author to demonstrate validation in the offline demo. It was NOT produced by a language model.

Provider `scripted`, model `scripted-example`, prompt version 2026-10-11.1. 7 of 7 claims passed the checks (cited evidence exists, the quote appears in it word for word, numbers and dates match). That shows grounding, not that the reasoning is right. Ratings are opinions, not probabilities.

**Exploit-development difficulty:** `insufficient_evidence`
- *Prerequisites:* cups-browsed listens on port 631 on all interfaces and trusts packets from any source. (fact) [CVE.desc] — quote: “binds to `INADDR_ANY:631`, causing it to trust any packet from any source”
- *Prerequisites:* Code execution is described only when chained with other CVEs and when a user prints to the attacker's printer. (fact) [CVE.desc] — quote: “When combined with other vulnerabilities”
- *Complexity:* On its own this CVE is scored as integrity-low with no confidentiality or availability impact; the severe outcome depends on the chain. (inference) [CVE.cvss.1, CVE.desc] — quote: “CVSS 3.1 base score 5.3 (MEDIUM)”
- *Research availability:* NVD tags a researcher write-up and the vendor advisory as exploit references. (fact) [NVD.ref.1, NVD.ref.2] — quote: “NVD reference tagged 'Exploit'”

**Existing-exploit usability:** `public_exploit_claimed`
- *Exploit evidence:* CISA SSVC records Exploitation=poc and Automatable=no. (fact) [CVE.ssvc] — quote: “SSVC decision points: Exploitation=poc, Automatable=no”
- *Reliability limits:* Full impact requires user interaction (printing to a malicious printer), which limits automated exploitation. (inference) [CVE.desc, CVE.ssvc] — quote: “when a malicious printer is printed to”
- *Required access:* Network access to port 631 on the target; no authentication. (fact) [CVE.desc, CVE.cvss.1] — quote: “trust any packet from any source”

*Scripted summary (uncited free text):* Network-reachable cups-browsed accepts attacker-supplied printer data; serious impact requires chaining and a user print action.

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| print-srv-01 | cups-browsed 2.0.1 | affected | [affected] CNA:GitHub_M 'cups-browsed': name 'cups browsed': matches free-text constraint '&lt;= 2.0.1' (parsed as &lt;= 2.0.1) |

### Severity score details

| Source | CVSS version | Score | Rating | Evidence |
|---|---|---|---|---|
| GitHub_M, which published the CVE **(used)** | 3.1 | 5.3 | Medium | CVE.cvss.1 |
| github.com | 3.1 | 5.3 | Medium | NVD.cvss.1 |

What the 5.3 score says: Attack from: the network (remotely); Attack complexity: low — no special conditions; Login / privileges needed: none; A user must do something: no; Impact spreads beyond the component: no; Impact on confidentiality (data theft): none; Impact on integrity (data tampering): low; Impact on availability (outage): none (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`)

### Evidence

| ID | Source | Summary | Retrieved | Published / updated | URL |
|---|---|---|---|---|---|
| CVE.state | cve_org (demo) | CVE record state PUBLISHED (assigner GitHub_M, data version 5.2). | 2026-10-10T21:13:37+00:00 | 2024-09-26T21:13:05.913Z / 2025-11-04T21:08:56.576Z | https://cveawg.mitre.org/api/cve/CVE-2024-47176 |
| CVE.desc | cve_org (demo) | CNA description of the vulnerability (verbatim, untrusted text). | 2026-10-10T21:13:37+00:00 | 2024-09-26T21:13:05.913Z / 2025-11-04T21:08:56.576Z | https://cveawg.mitre.org/api/cve/CVE-2024-47176 |
| CVE.cwe | cve_org (demo) | CNA weakness classification: CWE-1327 | 2026-10-10T21:13:37+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-47176 |
| CVE.cvss.1 | cve_org (demo) | CVSS 3.1 base score 5.3 (MEDIUM) from CNA:GitHub_M [cna] | 2026-10-10T21:13:37+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-47176 |
| CVE.affected.1 | cve_org (demo) | CNA:GitHub_M lists affected product 'OpenPrinting / cups-browsed' with 1 version statement(s); default status unspecified. | 2026-10-10T21:13:37+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-47176 |
| CVE.ssvc | cve_org (demo) | CISA-ADP SSVC decision points: Exploitation=poc, Automatable=no, Technical Impact=partial (assessed 2024-09-27T18:10:15.456578Z). | 2026-10-10T21:13:37+00:00 | - / 2024-09-27T18:10:15.456578Z | https://cveawg.mitre.org/api/cve/CVE-2024-47176 |
| CVE.affected.2 | cve_org (demo) | ADP:CISA-ADP lists affected product 'openprinting / cups' with 1 version statement(s); default status unknown. | 2026-10-10T21:13:37+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-47176 |
| NVD.status | nvd (demo) | NVD analysis status: Modified (last modified 2026-06-17T07:56:40.690). | 2026-10-10T21:13:43+00:00 | 2024-09-26T22:15:04.497 / 2026-06-17T07:56:40.690 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-47176 |
| NVD.cvss.1 | nvd (demo) | CVSS 3.1 base score 5.3 (MEDIUM) from security-advisories@github.com [Secondary] | 2026-10-10T21:13:43+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-47176 |
| NVD.cwe | nvd (demo) | NVD weakness classification: CWE-1327 | 2026-10-10T21:13:43+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-47176 |
| NVD.cpe | nvd (demo) | NVD lists 1 vulnerable CPE match criteria. | 2026-10-10T21:13:43+00:00 | - / 2026-06-17T07:56:40.690 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-47176 |
| NVD.ref.1 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:43+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-47176 → ref: https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8 |
| NVD.ref.2 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:43+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-47176 → ref: https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I |
| NVD.ref.3 | nvd (demo) | NVD reference tagged Patch. | 2026-10-10T21:13:43+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-47176 → ref: https://github.com/OpenPrinting/cups-browsed/commit/1debe6b140c37e0aa928559add4abcc95ce54aa2 |
| UBUNTU | ubuntu (demo) | Ubuntu security tracker: status for 2 source package(s) across Ubuntu releases. | 2026-10-11T17:36:54+00:00 | 2024-10-06T19:00:00 / 2025-08-26T10:50:31.260058+00:00 | https://ubuntu.com/security/cves/CVE-2024-47176.json |
| KEV | cisa_kev (demo) | Not listed in CISA KEV catalogue version 2026.10.08. Absence does NOT show the vulnerability is unexploited — only that CISA has not added it. | 2026-10-10T21:14:10+00:00 | 2026-10-08T20:09:18.9833Z / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 0.5060 (percentile 0.9889) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:43+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2024-47176 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok; ubuntu=ok

## CVE-2024-3094 — Not applicable to the supplied inventory

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Official description (copied word for word; untrusted text) [CVE.desc]:* Xz: malicious code in distributed source — Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0.  Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

**Decision:** Not affected — no action needed · **Severity score alone would say:** P1

**In short:** Your installed version is outside the affected versions: ops-ubuntu-02's xz 5.4.6. For reference (it does not change the decision): attacks are likely — the predicted chance of attacks in the next 30 days is 86.0%. No confirmed attacks are on record.

### What is known (sourced facts)
- CVE status: Published (active) — assigned by redhat; published 2024-03-29; last updated 2026-08-04 [CVE.state]
- Severity: 10.0 / 10 (Critical) — CVSS 3.1 score from redhat, which published the CVE; 3 sources agree. Full breakdown in Severity score details. [CVE.cvss.1]
- Type of flaw: Embedded Malicious Code — CWE-506: Embedded Malicious Code. CWE = MITRE's Common Weakness Enumeration. [CVE.cwe, NVD.cwe]
- On the US government's list of actively attacked flaws (KEV): No — Not in KEV catalogue 2026.10.08 (absence is not evidence of no exploitation). [KEV]
- CISA's rating: no attacks or attack code known — CISA SSVC decision points: Exploitation=none, Automatable=yes, Technical Impact=total; assessed 2024-04-02. [CVE.ssvc]
- Predicted chance of attacks in the next 30 days: 86.0% — EPSS 0.8597, higher than 99.7% of all scored CVEs, scored 2026-10-10 (FIRST EPSS model). Estimates exploitation activity, not difficulty or impact. [EPSS]
- ops-ubuntu-02: xz 5.4.6 is not affected — Red Hat's CVE record: your version is not listed, and the record marks unlisted versions as not affected. NVD: version 5.4.6 is outside all 2 affected ranges. [CVE.affected.1, NVD.cpe]

### What remains uncertain
- Known to be exploited by attackers: Unknown — No positive evidence of in-the-wild exploitation in the sources checked. This is not proof that exploitation has not occurred. [KEV, CVE.ssvc]
- Attack code reported to be public: Unknown — No exploit-tagged references or SSVC PoC signal found. Exploit databases were not searched.
- Some evidence may be out of date — SSVC Exploitation=none was assessed 2024-04-02 (> 180 days ago) and may no longer reflect current activity. [CVE.ssvc]
- Demo data: the attacked-flaws list (KEV) is a reduced copy — Offline demo uses a trimmed KEV fixture; absence was verified against the full catalogue at capture time only.
- Little public research doesn't mean it's hard to exploit — Exploit-development difficulty judged from public evidence is inherently limited: the absence of public research does not mean exploitation is hard.

### Why this priority (rule trace)
1. Starts at P2: the predicted chance of attacks in the next 30 days is 86.0% — rule: a CISA proof-of-concept rating, a predicted chance of attacks of 10% or more, or a validated AI rating of 'easy to exploit' each start at P2.
2. No priority: your installed versions are not affected — all matching inventory items are outside the affected versions.

### Action supported by the evidence
- No action needed for the listed systems — keep the inventory accurate and re-check if versions change.

### What would change the recommendation
- If the sources' disagreements are resolved → the decision may change — see 'What's uncertain' for which sources disagree.

### AI-assisted assessment (judgement, not fact)

Status: `not_configured` — not_configured: no scripted example for CVE-2024-3094

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| ops-ubuntu-02 | xz 5.4.6 | not_affected | [not_affected] CNA:redhat 'xz': name 'xz': version not listed; source default status is 'unaffected'; [not_affected] NVD tukaani:xz: version 5.4.6 outside all 2 NVD ranges |

### Severity score details

| Source | CVSS version | Score | Rating | Evidence |
|---|---|---|---|---|
| redhat, which published the CVE **(used)** | 3.1 | 10.0 | Critical | CVE.cvss.1 |
| redhat.com | 3.1 | 10.0 | Critical | NVD.cvss.1 |
| NVD | 3.1 | 10.0 | Critical | NVD.cvss.2 |

What the 10.0 score says: Attack from: the network (remotely); Attack complexity: low — no special conditions; Login / privileges needed: none; A user must do something: no; Impact spreads beyond the component: yes; Impact on confidentiality (data theft): high; Impact on integrity (data tampering): high; Impact on availability (outage): high (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`)

### Evidence

| ID | Source | Summary | Retrieved | Published / updated | URL |
|---|---|---|---|---|---|
| CVE.state | cve_org (demo) | CVE record state PUBLISHED (assigner redhat, data version 5.2). | 2026-10-10T21:13:17+00:00 | 2024-03-29T16:51:12.588Z / 2026-08-04T07:05:54.671Z | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| CVE.desc | cve_org (demo) | CNA description of the vulnerability (verbatim, untrusted text). | 2026-10-10T21:13:17+00:00 | 2024-03-29T16:51:12.588Z / 2026-08-04T07:05:54.671Z | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| CVE.cwe | cve_org (demo) | CNA weakness classification: CWE-506 | 2026-10-10T21:13:17+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| CVE.cvss.1 | cve_org (demo) | CVSS 3.1 base score 10 (CRITICAL) from CNA:redhat [cna] | 2026-10-10T21:13:17+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| CVE.affected.1 | cve_org (demo) | CNA:redhat lists affected product '- / xz' with 2 version statement(s); default status unaffected. | 2026-10-10T21:13:17+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| CVE.affected.2 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 10' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:17+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| CVE.affected.3 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 6' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:17+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| CVE.affected.4 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 7' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:17+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| CVE.affected.5 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 8' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:17+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| CVE.affected.6 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat Enterprise Linux 9' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:17+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| CVE.affected.7 | cve_org (demo) | CNA:redhat lists affected product 'Red Hat / Red Hat JBoss Enterprise Application Platform 8' with 0 version statement(s); default status unaffected. | 2026-10-10T21:13:17+00:00 | - / - | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| CVE.ssvc | cve_org (demo) | CISA-ADP SSVC decision points: Exploitation=none, Automatable=yes, Technical Impact=total (assessed 2024-04-02T04:00:23.138684Z). | 2026-10-10T21:13:17+00:00 | - / 2024-04-02T04:00:23.138684Z | https://cveawg.mitre.org/api/cve/CVE-2024-3094 |
| NVD.status | nvd (demo) | NVD analysis status: Modified (last modified 2026-06-17T07:43:17.830). | 2026-10-10T21:13:24+00:00 | 2024-03-29T17:15:21.150 / 2026-06-17T07:43:17.830 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094 |
| NVD.cvss.1 | nvd (demo) | CVSS 3.1 base score 10.0 (CRITICAL) from secalert@redhat.com [Secondary] | 2026-10-10T21:13:24+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094 |
| NVD.cvss.2 | nvd (demo) | CVSS 3.1 base score 10.0 (CRITICAL) from nvd@nist.gov [Primary] | 2026-10-10T21:13:24+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094 |
| NVD.cwe | nvd (demo) | NVD weakness classification: CWE-506 | 2026-10-10T21:13:24+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094 |
| NVD.cpe | nvd (demo) | NVD lists 2 vulnerable CPE match criteria. | 2026-10-10T21:13:24+00:00 | - / 2026-06-17T07:43:17.830 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094 |
| NVD.ref.1 | nvd (demo) | NVD reference tagged Vendor Advisory. | 2026-10-10T21:13:24+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094 → ref: https://access.redhat.com/security/cve/CVE-2024-3094 |
| NVD.ref.2 | nvd (demo) | NVD reference tagged Issue Tracking, Vendor Advisory. | 2026-10-10T21:13:24+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094 → ref: https://bugzilla.redhat.com/show_bug.cgi?id=2272210 |
| NVD.ref.3 | nvd (demo) | NVD reference tagged Vendor Advisory. | 2026-10-10T21:13:24+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094 → ref: https://www.redhat.com/en/blog/urgent-security-alert-fedora-41-and-rawhide-users |
| NVD.ref.4 | nvd (demo) | NVD reference tagged Mailing List, Vendor Advisory. | 2026-10-10T21:13:24+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094 → ref: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1068024 |
| NVD.ref.5 | nvd (demo) | NVD reference tagged Issue Tracking, Vendor Advisory. | 2026-10-10T21:13:24+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094 → ref: https://tukaani.org/xz-backdoor/ |
| UBUNTU | ubuntu (demo) | Ubuntu security tracker: status for 1 source package(s) across Ubuntu releases. | 2026-10-11T17:30:20+00:00 | 2024-03-29T17:15:00 / 2025-08-04T20:04:01.548605+00:00 | https://ubuntu.com/security/cves/CVE-2024-3094.json |
| KEV | cisa_kev (demo) | Not listed in CISA KEV catalogue version 2026.10.08. Absence does NOT show the vulnerability is unexploited — only that CISA has not added it. | 2026-10-10T21:14:10+00:00 | 2026-10-08T20:09:18.9833Z / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 0.8597 (percentile 0.9973) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:24+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2024-3094 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok; ubuntu=ok

## CVE-2026-11415 — Rejected CVE — no remediation needed

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

**Decision:** Cancelled CVE — no action needed · **Severity score alone would say:** N/A

**In short:** This CVE was cancelled (rejected) by the organisation that issued it, so there is nothing to fix.

### What is known (sourced facts)
- CVE status: Cancelled (rejected) — assigned by VulnCheck; last updated 2026-09-29 [CVE.state]
- Reason given for rejection — (source text) This CVE ID has been rejected or withdrawn by its CVE Numbering Authority. [CVE.rejected]

### What remains uncertain
- Nothing flagged.

### Why this priority (rule trace)
1. No priority: this CVE was cancelled — the CVE record is REJECTED, so there is nothing to fix.

### Action supported by the evidence
- No fix needed: this CVE was rejected — remove it from tracking and check whether the issue was re-assigned under another CVE ID [CVE.rejected].

### What would change the recommendation
- No single input change identified.

### AI-assisted assessment (judgement, not fact)

Status: `skipped` — Not run: record is rejected.

### Evidence

| ID | Source | Summary | Retrieved | Published / updated | URL |
|---|---|---|---|---|---|
| CVE.state | cve_org (demo) | CVE record state REJECTED (assigner VulnCheck, data version 5.2). | 2026-10-10T21:13:50+00:00 | - / 2026-09-29T19:32:51.685Z | https://cveawg.mitre.org/api/cve/CVE-2026-11415 |
| CVE.rejected | cve_org (demo) | Record is REJECTED by its CNA. | 2026-10-10T21:13:50+00:00 | - / 2026-09-29T19:32:51.685Z | https://cveawg.mitre.org/api/cve/CVE-2026-11415 |
| NVD.status | nvd (demo) | NVD analysis status: Rejected (last modified 2026-09-29T20:17:18.983). | 2026-10-10T21:13:56+00:00 | 2026-09-29T20:17:18.983 / 2026-09-29T20:17:18.983 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-11415 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=not_found

## CVE-2026-99001 — No published record — cannot assess

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

**Decision:** Not published yet — check again later · **Severity score alone would say:** N/A

**In short:** This CVE number has been reserved, but no details have been published yet.

### What is known (sourced facts)
- CVE status: Reserved, no details published yet — CVE ID is RESERVED: assigned but no public record has been published. [CVE.state]

### What remains uncertain
- Nothing about this flaw is known yet — No details are public, so the affected products, severity and attack activity are all unknown. This is not a sign that your systems are safe; check again after publication. [CVE.state]

### Why this priority (rule trace)
1. No priority: there are no public details — the CVE ID is reserved but not yet published.

### Action supported by the evidence
- Check the CVE ID and look again later — a reserved ID has no public details yet [CVE.state].

### What would change the recommendation
- The record is published with affected products and severity → it can then be assessed like any other CVE, at any priority

### AI-assisted assessment (judgement, not fact)

Status: `skipped` — Not run: record is reserved.

### Evidence

| ID | Source | Summary | Retrieved | Published / updated | URL |
|---|---|---|---|---|---|
| CVE.state | cve_org (demo) | CVE ID is RESERVED: assigned but no public record has been published. | 2026-10-10T21:13:57+00:00 | - / - | https://cveawg.mitre.org/api/cve-id/CVE-2026-99001 |

**Source retrieval status:** cve_org=not_found; nvd=not_found; cisa_kev=ok; first_epss=not_found
