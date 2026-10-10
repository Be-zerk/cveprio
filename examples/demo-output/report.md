# CVE prioritization report

Generated 2026-10-10T22:17:36+00:00 · mode **offline_demo** · cveprio 0.1.0 · organisation: Northbeam Logistics (fictional)

> OFFLINE DEMO MODE: data comes from recorded fixtures (see retrieval times), not live sources. Results may be out of date.
> Inventory and business context are FICTIONAL example data.
> This product uses the NVD API but is not endorsed or certified by the NVD.
> CVE records: CVE Program (cve.org). KEV: CISA Known Exploited Vulnerabilities catalogue (CC0). EPSS: FIRST.org Exploit Prediction Scoring System (https://www.first.org/epss).

| CVE | Decision | Baseline (CVSS only) | Exploitation | Severity | Exposure |
|---|---|---|---|---|---|
| CVE-2021-44228 | P1 | P1 | confirmed | critical | high |
| CVE-2023-44487 | P1 | P2 | confirmed | high | high |
| CVE-2024-6387 | P1 | P2 | elevated | high | high |
| CVE-2023-38545 | P2 (provisional) | P1 | elevated | critical | context_unknown |
| CVE-2022-22965 | NEEDS_REVIEW (provisional) | P1 | confirmed | critical | needs_review |
| CVE-2024-47176 | P3 | P3 | elevated | medium | reduced |
| CVE-2024-3094 | NOT_APPLICABLE | P1 | elevated | critical | not_affected |
| CVE-2026-11415 | NO_ACTION_REJECTED | N/A | n/a | n/a | n/a |
| CVE-2026-99001 | INVALID_OR_UNPUBLISHED | N/A | n/a | n/a | n/a |

## CVE-2021-44228 — P1: Act now: emergency change / out-of-band patching

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Source description (untrusted text, verbatim) [CVE.desc]:* Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints — Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that t

**Decision:** `P1` · priority P1

**Factors:** exploitation = `confirmed`, severity = `critical`, exposure = `high` · **Severity-only baseline:** `P1`

### What is known (sourced facts)
- CVE record state PUBLISHED (assigner apache, data version 5.1). [CVE.state]
- Most severe CVSS 3.1: 10.0 CRITICAL (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) from ADP:CISA-ADP [CVE.cvss.1]
- Weakness: CWE-20, CWE-400, CWE-502, CWE-917 [CVE.cwe, NVD.cwe]
- Kev listed: true — Listed in the CISA Known Exploited Vulnerabilities catalogue. [KEV]
- Exploited in wild: true — Positive evidence of exploitation in the wild (KEV listing and/or CISA SSVC Exploitation=active). [KEV, CVE.ssvc]
- Public exploit claimed: true — 12 source item(s) indicate public exploit/PoC material. Existence, reliability and impact of that code are NOT verified by this tool. [CVE.ssvc, NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, NVD.ref.11, NVD.ref.14, NVD.ref.15]
- CISA-ADP SSVC decision points: Exploitation=active, Automatable=yes, Technical Impact=total (assessed 2025-02-04T14:25:34.416117Z). [CVE.ssvc]
- EPSS 1.0000 (percentile 1.0000) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. [EPSS]
- web-portal-01: log4j-core 2.14.1 → affected [NVD.cpe] (matched by NVD apache:log4j)

### What remains uncertain
- legacy-billing-03: Log4j 2.x (bundled by appliance vendor) → needs_review [CVE.affected.1] — No exact product match; similar product names found (similarity does not establish that this deployment is affected):; CNA:apache: similar name: 'log4j' vs 'apache log4j2'

### Why this priority (rule trace)
1. Base P1: exploitation confirmed (KEV and/or SSVC active).
2. Exposure high (internet-facing or high-criticality asset) → P1.
3. Other assets need version review: legacy-billing-03

### Action supported by the evidence
- Upgrade log4j-core 2.14.1 on web-portal-01 to a fixed release (sources indicate fixed at/after 2.15.0) [NVD.ref.9, NVD.ref.10, NVD.ref.12].
- Confirm the exact build/version (and any platform condition) of Log4j 2.x (bundled by appliance vendor) on legacy-billing-03, then re-run; see reasons [CVE.affected.1].
- CISA KEV required action (quoted source text) [KEV]: For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available.

### What would change the recommendation
- If a verified compensating control removes reachability → P2
- Once the fix is applied and verified → NOT_APPLICABLE

### AI-assisted assessment (judgement, not fact)

Status: `not_configured` — not_configured: no scripted example for CVE-2021-44228

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| web-portal-01 | log4j-core 2.14.1 | affected | [affected] NVD apache:log4j: in range ≥2.13.0 &lt;2.15.0 |
| legacy-billing-03 | Log4j 2.x (bundled by appliance vendor) | needs_review | No exact product match; similar product names found (similarity does not establish that this deployment is affected):; CNA:apache: similar name: 'log4j' vs 'apache log4j2' |

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
| NVD.cvss.2 | nvd (demo) | CVSS 3.1 base score 10.0 (CRITICAL) from 134c704f-9b21-4f2e-91b3-4a467353bcc0 [Secondary] | 2026-10-10T21:13:11+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 |
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
| KEV | cisa_kev (demo) | Listed in CISA KEV (added 2021-12-10; known ransomware use: Known; federal due date 2021-12-24). | 2026-10-10T21:14:10+00:00 | 2021-12-10 / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 1.0000 (percentile 1.0000) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:11+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2021-44228 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok

## CVE-2023-44487 — P1: Act now: emergency change / out-of-band patching

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Source description (untrusted text, verbatim) [CVE.desc]:*  — The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

**Decision:** `P1` · priority P1

**Factors:** exploitation = `confirmed`, severity = `high`, exposure = `high` · **Severity-only baseline:** `P2`

### What is known (sourced facts)
- CVE record state PUBLISHED (assigner mitre, data version 5.2). [CVE.state]
- Most severe CVSS 3.1: 7.5 HIGH (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) from ADP:CISA-ADP [CVE.cvss.1]
- Weakness: CWE-400 [NVD.cwe]
- Kev listed: true — Listed in the CISA Known Exploited Vulnerabilities catalogue. [KEV]
- Exploited in wild: true — Positive evidence of exploitation in the wild (KEV listing and/or CISA SSVC Exploitation=active). [KEV, CVE.ssvc]
- Public exploit claimed: true — 3 source item(s) indicate public exploit/PoC material. Existence, reliability and impact of that code are NOT verified by this tool. [CVE.ssvc, NVD.ref.11, NVD.ref.12]
- CISA-ADP SSVC decision points: Exploitation=active, Automatable=yes, Technical Impact=partial (assessed 2024-07-23T20:34:21.334116Z). [CVE.ssvc]
- EPSS 1.0000 (percentile 1.0000) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. [EPSS]
- web-portal-01: nginx 1.25.2 → affected [NVD.cpe] (matched by NVD f5:nginx)

### What remains uncertain
- Nothing flagged.

### Why this priority (rule trace)
1. Base P1: exploitation confirmed (KEV and/or SSVC active).
2. Exposure high (internet-facing or high-criticality asset) → P1.

### Action supported by the evidence
- Upgrade nginx 1.25.2 on web-portal-01 per the vendor advisory [NVD.ref.1, NVD.ref.2, NVD.ref.3].
- CISA KEV required action (quoted source text) [KEV]: Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

### What would change the recommendation
- If a verified compensating control removes reachability → P2
- Once the fix is applied and verified → NOT_APPLICABLE

### AI-assisted assessment (judgement, not fact)

Status: `not_configured` — not_configured: no scripted example for CVE-2023-44487

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| web-portal-01 | nginx 1.25.2 | affected | [affected] NVD f5:nginx: in range ≥1.9.5 ≤1.25.2 |

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
| NVD.cvss.2 | nvd (demo) | CVSS 3.1 base score 7.5 (HIGH) from 134c704f-9b21-4f2e-91b3-4a467353bcc0 [Secondary] | 2026-10-10T21:13:30+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487 |
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
| KEV | cisa_kev (demo) | Listed in CISA KEV (added 2023-10-10; known ransomware use: Unknown; federal due date 2023-10-31). | 2026-10-10T21:14:10+00:00 | 2023-10-10 / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 1.0000 (percentile 1.0000) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:30+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2023-44487 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok

## CVE-2024-6387 — P1: Act now: emergency change / out-of-band patching

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Source description (untrusted text, verbatim) [CVE.desc]:* Openssh: regresshion - race condition in ssh allows rce/dos — A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

**Decision:** `P1` · priority P1

**Factors:** exploitation = `elevated`, severity = `high`, exposure = `high` · **Severity-only baseline:** `P2`

### What is known (sourced facts)
- CVE record state PUBLISHED (assigner redhat, data version 5.2). [CVE.state]
- Most severe CVSS 3.1: 8.1 HIGH (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) from CNA:redhat [CVE.cvss.1]
- Weakness: CWE-364, CWE-362 [CVE.cwe, NVD.cwe]
- Kev listed: false — Not in KEV catalogue 2026.10.08 (absence is not evidence of no exploitation). [KEV]
- Public exploit claimed: true — 10 source item(s) indicate public exploit/PoC material. Existence, reliability and impact of that code are NOT verified by this tool. [CVE.ssvc, NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, NVD.ref.12, NVD.ref.13]
- CISA-ADP SSVC decision points: Exploitation=poc, Automatable=no, Technical Impact=total (assessed 2024-07-02T13:18:34.695298Z). [CVE.ssvc]
- EPSS 0.9951 (percentile 0.9994) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. [EPSS]
- bastion-01: OpenSSH 9.6p1 → affected [CVE.affected.1, NVD.cpe] (matched by CNA:redhat 'OpenSSH')

### What remains uncertain
- Exploited in wild: unknown — No positive evidence of in-the-wild exploitation in the sources checked. This is not proof that exploitation has not occurred. [KEV, CVE.ssvc]
- ops-ubuntu-02: OpenSSH 1:9.6p1-3ubuntu13.4 → needs_review [CVE.affected.1] — [ambiguous] CNA:redhat 'OpenSSH': name 'openssh': cannot compare '1:9.6p1-3ubuntu13.4' with range 8.5p1..9.7p1 (custom); '1:9.6p1-3ubuntu13.4' looks like a distribution package version; vendors often backport fixes without changing the upstream version — check the distribution's advisory.
- Conflict (stale_signal): SSVC Exploitation=poc was assessed 2024-07-02 (> 180 days ago) and may no longer reflect current activity. [CVE.ssvc]
- Offline demo uses a trimmed KEV fixture; absence was verified against the full catalogue at capture time only.
- Open question (scripted demo example): Which builds and architectures do the public PoCs target, and how many attempts do they need?
- Open question (scripted demo example): Has in-the-wild exploitation been reported since the SSVC assessment date?
- Exploit-development difficulty from public evidence is inherently limited: the absence of public research does not mean exploitation is hard.

### Why this priority (rule trace)
1. Base P2: exploitation signal elevated (public exploit claimed, EPSS ≥ 0.10, or validated AI difficulty=low).
2. Exposure high (internet-facing or high-criticality asset) → P1.
3. Other assets need version review: ops-ubuntu-02

### Action supported by the evidence
- Upgrade OpenSSH 9.6p1 on bastion-01 per the vendor advisory [NVD.ref.4, NVD.ref.9, NVD.ref.10].
- Confirm the exact build/version (and any platform condition) of OpenSSH 1:9.6p1-3ubuntu13.4 on ops-ubuntu-02, then re-run; see reasons [CVE.affected.1].

### What would change the recommendation
- If a verified compensating control removes reachability → P3
- Once the fix is applied and verified → NOT_APPLICABLE
- Resolving the listed source conflicts could change the inputs above.

### AI-assisted assessment (judgement, not fact)

> **SCRIPTED EXAMPLE** — hand-written by the project author to demonstrate validation in the offline demo. It was NOT produced by a language model.

Provider `scripted`, model `scripted-example`. Claims with valid citation IDs: 6/8 (cited IDs exist, but whether the source actually says what the claim says is NOT checked). Ratings are qualitative; no calibrated probability is implied.

**Exploit-development difficulty:** `moderate`
- *Prerequisites:* The attacker needs only network access to sshd and no credentials; the trigger is failing to authenticate within the login time limit. (fact) [CVE.desc, CVE.cvss.1]
- *Complexity:* The flaw is a race condition in signal handling, and the CNA scores attack complexity as High, which suggests exploitation depends on winning a timing window. (inference) [CVE.desc, CVE.cvss.1]
- *Research availability:* Several references tagged 'Exploit' by NVD, including a researcher advisory, indicate detailed public research exists. (fact) [NVD.ref.2, NVD.ref.12]

**Existing-exploit usability:** `public_exploit_claimed`
- *Exploit evidence:* CISA's SSVC assessment records Exploitation=poc. (fact) [CVE.ssvc]
- *Reliability limits:* A race-condition exploit is likely to need many connection attempts, which may be visible in authentication logs. (inference) [CVE.desc, CVE.cvss.1]
- *Required access:* Network reachability to the SSH service; no privileges or user interaction. (fact) [CVE.cvss.1]

*Scripted summary (uncited free text):* Unauthenticated remote race condition in sshd with public research and PoC claims; timing complexity is the main barrier.

**Validation removed/overrode:**
- `difficulty.complexity_factors[1]`: cites unknown evidence ID(s): ['NVD.ref.99'] — “Exploitation is reliable on all Linux distributions.”
- `difficulty.research_availability[1]`: no evidence cited — “Public write-ups make weaponisation trivial.”
- `usability.rating`: rating 'exploitation_reported' → 'public_exploit_claimed': no source in the bundle reports in-the-wild exploitation

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| bastion-01 | OpenSSH 9.6p1 | affected | [affected] CNA:redhat 'OpenSSH': name 'openssh': in range 8.5p1..≤9.7p1 → affected; [affected] NVD openbsd:openssh: in range ≥8.6 ≤9.8 |
| ops-ubuntu-02 | OpenSSH 1:9.6p1-3ubuntu13.4 | needs_review | [ambiguous] CNA:redhat 'OpenSSH': name 'openssh': cannot compare '1:9.6p1-3ubuntu13.4' with range 8.5p1..9.7p1 (custom); '1:9.6p1-3ubuntu13.4' looks like a distribution package version; vendors often backport fixes without changing the upstream version — check the distribution's advisory. |

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
| KEV | cisa_kev (demo) | Not listed in CISA KEV catalogue version 2026.10.08. Absence does NOT show the vulnerability is unexploited — only that CISA has not added it. | 2026-10-10T21:14:10+00:00 | 2026-10-08T20:09:18.9833Z / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 0.9951 (percentile 0.9994) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:17+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2024-6387 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok

## CVE-2023-38545 — P2: Next patch cycle, ahead of routine work (provisional)

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Source description (untrusted text, verbatim) [CVE.desc]:*  — This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake.  When curl is asked to pass along the host name to the SOCKS5 proxy to allow that to resolve the address instead of it getting done by curl itself, the maximum length that host name can be is 255 bytes.  If the host name is detected to be longer, curl switches to local name resolving and instead passes on the resolved address only. Due to this bug, the local variable that means "let the host resolve the name" could get the wrong value during a slow SOCKS5 handshake, and contrary to the intention, copy the too long host name to the target buffer instead of copying just the resolved address there.  The target b

**Decision:** `P2` · priority P2 · provisional

**Factors:** exploitation = `elevated`, severity = `critical`, exposure = `context_unknown` · **Severity-only baseline:** `P1`

### What is known (sourced facts)
- CVE record state PUBLISHED (assigner hackerone, data version 5.2). [CVE.state]
- Most severe CVSS 3.1: 9.8 CRITICAL (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) from nvd@nist.gov [NVD.cvss.1]
- Weakness: CWE-787 [NVD.cwe]
- Kev listed: false — Not in KEV catalogue 2026.10.08 (absence is not evidence of no exploitation). [KEV]
- Public exploit claimed: true — 1 source item(s) indicate public exploit/PoC material. Existence, reliability and impact of that code are NOT verified by this tool. [CVE.ssvc]
- CISA-ADP SSVC decision points: Exploitation=poc, Automatable=no, Technical Impact=total (assessed 2024-10-17T21:11:03.346985Z). [CVE.ssvc]
- EPSS 0.7848 (percentile 0.9958) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. [EPSS]
- ops-ubuntu-02: curl 8.3.0 → affected [NVD.cpe] (matched by NVD haxx:libcurl)
- dev-laptop-17: curl 8.3.0 → affected [NVD.cpe] (matched by NVD haxx:libcurl)

### What remains uncertain
- Exploited in wild: unknown — No positive evidence of in-the-wild exploitation in the sources checked. This is not proof that exploitation has not occurred. [KEV, CVE.ssvc]
- Conflict (cvss_disagreement): Sources disagree on CVSS 3.1 base score: ADP:CISA-ADP 8.8; nvd@nist.gov 9.8; 134c704f-9b21-4f2e-91b3-4a467353bcc0 8.8. Rules use the most severe value; verify against the vendor advisory. [CVE.cvss.1, NVD.cvss.1, NVD.cvss.2]
- Conflict (stale_signal): SSVC Exploitation=poc was assessed 2024-10-17 (> 180 days ago) and may no longer reflect current activity. [CVE.ssvc]
- Offline demo uses a trimmed KEV fixture; absence was verified against the full catalogue at capture time only.
- Exploit-development difficulty from public evidence is inherently limited: the absence of public research does not mean exploitation is hard.

### Why this priority (rule trace)
1. Base P2: exploitation signal elevated (public exploit claimed, EPSS ≥ 0.10, or validated AI difficulty=low).
2. Asset context missing (internet exposure/criticality not supplied) → unchanged, provisional.
3. dev-laptop-17: context missing (internet_facing, criticality); not assumed.

### Action supported by the evidence
- Upgrade curl 8.3.0 on ops-ubuntu-02 to a fixed release (sources indicate fixed at/after 8.4.0) [NVD.ref.1, NVD.ref.2].
- Upgrade curl 8.3.0 on dev-laptop-17 to a fixed release (sources indicate fixed at/after 8.4.0) [NVD.ref.1, NVD.ref.2].

### What would change the recommendation
- If exploitation in the wild is reported (e.g. KEV listing) → P1
- If the affected asset is internet-facing or high-criticality → P1
- Resolving the listed source conflicts could change the inputs above.

### AI-assisted assessment (judgement, not fact)

Status: `not_configured` — not_configured: no scripted example for CVE-2023-38545

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| ops-ubuntu-02 | curl 8.3.0 | affected | [affected] NVD haxx:libcurl: in range ≥7.69.0 &lt;8.4.0 |
| dev-laptop-17 | curl 8.3.0 | affected | [affected] NVD haxx:libcurl: in range ≥7.69.0 &lt;8.4.0 |

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
| NVD.cvss.2 | nvd (demo) | CVSS 3.1 base score 8.8 (HIGH) from 134c704f-9b21-4f2e-91b3-4a467353bcc0 [Secondary] | 2026-10-10T21:13:37+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 |
| NVD.cwe | nvd (demo) | NVD weakness classification: CWE-787 | 2026-10-10T21:13:37+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 |
| NVD.cpe | nvd (demo) | NVD lists 14 vulnerable CPE match criteria. | 2026-10-10T21:13:37+00:00 | - / 2026-06-17T06:10:41.627 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 |
| NVD.ref.1 | nvd (demo) | NVD reference tagged Patch, Third Party Advisory. | 2026-10-10T21:13:37+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 → ref: https://curl.se/docs/CVE-2023-38545.html |
| NVD.ref.2 | nvd (demo) | NVD reference tagged Patch, Third Party Advisory. | 2026-10-10T21:13:37+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-38545 → ref: https://www.secpod.com/blog/high-severity-heap-buffer-overflow-vulnerability/ |
| KEV | cisa_kev (demo) | Not listed in CISA KEV catalogue version 2026.10.08. Absence does NOT show the vulnerability is unexploited — only that CISA has not added it. | 2026-10-10T21:14:10+00:00 | 2026-10-08T20:09:18.9833Z / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 0.7848 (percentile 0.9958) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:37+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2023-38545 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok

## CVE-2022-22965 — Needs version review (would be P1 if affected)

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Source description (untrusted text, verbatim) [CVE.desc]:*  — A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

**Decision:** `NEEDS_REVIEW` · priority P1 · provisional

**Factors:** exploitation = `confirmed`, severity = `critical`, exposure = `needs_review` · **Severity-only baseline:** `P1`

### What is known (sourced facts)
- CVE record state PUBLISHED (assigner vmware, data version 5.1). [CVE.state]
- Most severe CVSS 3.1: 9.8 CRITICAL (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) from ADP:CISA-ADP [CVE.cvss.1]
- Weakness: CWE-94 [CVE.cwe, NVD.cwe]
- Kev listed: true — Listed in the CISA Known Exploited Vulnerabilities catalogue. [KEV]
- Exploited in wild: true — Positive evidence of exploitation in the wild (KEV listing and/or CISA SSVC Exploitation=active). [KEV, CVE.ssvc]
- Public exploit claimed: true — 2 source item(s) indicate public exploit/PoC material. Existence, reliability and impact of that code are NOT verified by this tool. [CVE.ssvc, NVD.ref.1]
- CISA-ADP SSVC decision points: Exploitation=active, Automatable=yes, Technical Impact=total (assessed 2025-01-29T17:52:10.886552Z). [CVE.ssvc]
- EPSS 0.9964 (percentile 0.9995) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. [EPSS]

### What remains uncertain
- web-portal-01: Spring Framework 5.3.17 → needs_review [CVE.affected.1, NVD.cpe] — [ambiguous] CNA:vmware 'Spring Framework': name 'spring framework': version statement 'Spring Framework versions 5.3.X prior to 5.3.18+, 5.2.x prior to 5.2.20+ and all' is not machine-comparable; [ambiguous] NVD vmware:spring_framework: in range ≥5.3.0 <5.3.18; NVD applies this only in combination with cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:* (AND configuration) — confirm that platform condition for this deployment

### Why this priority (rule trace)
1. Base P1: exploitation confirmed (KEV and/or SSVC active).
2. Applicability ambiguous → NEEDS_REVIEW; would be P1 if confirmed affected.

### Action supported by the evidence
- Confirm the exact build/version (and any platform condition) of Spring Framework 5.3.17 on web-portal-01, then re-run; see reasons [CVE.affected.1, NVD.cpe].
- CISA KEV required action (quoted source text) [KEV]: Apply updates per vendor instructions.

### What would change the recommendation
- If the affected asset is internet-facing or high-criticality → P1
- If the affected asset is internal and low/medium criticality → P1
- If the deployed version is confirmed NOT affected → NOT_APPLICABLE

### AI-assisted assessment (judgement, not fact)

Status: `not_configured` — not_configured: no scripted example for CVE-2022-22965

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| web-portal-01 | Spring Framework 5.3.17 | needs_review | [ambiguous] CNA:vmware 'Spring Framework': name 'spring framework': version statement 'Spring Framework versions 5.3.X prior to 5.3.18+, 5.2.x prior to 5.2.20+ and all' is not machine-comparable; [ambiguous] NVD vmware:spring_framework: in range ≥5.3.0 &lt;5.3.18; NVD applies this only in combination with cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:* (AND configuration) — confirm that platform condition for this deployment |

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
| NVD.cvss.2 | nvd (demo) | CVSS 3.1 base score 9.8 (CRITICAL) from 134c704f-9b21-4f2e-91b3-4a467353bcc0 [Secondary] | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 |
| NVD.cvss.3 | nvd (demo) | CVSS 2.0 base score 7.5 (HIGH) from nvd@nist.gov [Primary] | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 |
| NVD.cwe | nvd (demo) | NVD weakness classification: CWE-94 | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 |
| NVD.cpe | nvd (demo) | NVD lists 97 vulnerable CPE match criteria. | 2026-10-10T21:13:50+00:00 | - / 2026-06-17T04:29:15.610 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 |
| NVD.ref.1 | nvd (demo) | NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist at this URL. Not verified, not downloaded; reliability unknown. | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 → ref: http://packetstormsecurity.com/files/166713/Spring4Shell-Code-Execution.html |
| NVD.ref.2 | nvd (demo) | NVD reference tagged Patch, Third Party Advisory. | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 → ref: https://cert-portal.siemens.com/productcert/pdf/ssa-254054.pdf |
| NVD.ref.3 | nvd (demo) | NVD reference tagged Mitigation, Vendor Advisory. | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 → ref: https://tanzu.vmware.com/security/cve-2022-22965 |
| NVD.ref.4 | nvd (demo) | NVD reference tagged Patch, Third Party Advisory. | 2026-10-10T21:13:50+00:00 | - / - | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22965 → ref: https://www.oracle.com/security-alerts/cpujul2022.html |
| KEV | cisa_kev (demo) | Listed in CISA KEV (added 2022-04-04; known ransomware use: Unknown; federal due date 2022-04-25). | 2026-10-10T21:14:10+00:00 | 2022-04-04 / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 0.9964 (percentile 0.9995) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:50+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2022-22965 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok

## CVE-2024-47176 — P3: Scheduled remediation in normal maintenance

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Source description (untrusted text, verbatim) [CVE.desc]:* cups-browsed binds to `INADDR_ANY:631`, trusting any packet from any source — CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL. When combined with other vulnerabilities, such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker can execute arbitrary commands remotely on the target machine without authentication when a malicious printer is printed to.

**Decision:** `P3` · priority P3

**Factors:** exploitation = `elevated`, severity = `medium`, exposure = `reduced` · **Severity-only baseline:** `P3`

### What is known (sourced facts)
- CVE record state PUBLISHED (assigner GitHub_M, data version 5.2). [CVE.state]
- Most severe CVSS 3.1: 5.3 MEDIUM (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N) from CNA:GitHub_M [CVE.cvss.1]
- Weakness: CWE-1327 [CVE.cwe, NVD.cwe]
- Kev listed: false — Not in KEV catalogue 2026.10.08 (absence is not evidence of no exploitation). [KEV]
- Public exploit claimed: true — 3 source item(s) indicate public exploit/PoC material. Existence, reliability and impact of that code are NOT verified by this tool. [CVE.ssvc, NVD.ref.1, NVD.ref.2]
- CISA-ADP SSVC decision points: Exploitation=poc, Automatable=no, Technical Impact=partial (assessed 2024-09-27T18:10:15.456578Z). [CVE.ssvc]
- EPSS 0.5060 (percentile 0.9889) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. [EPSS]
- print-srv-01: cups-browsed 2.0.1 → affected [CVE.affected.1] (matched by CNA:GitHub_M 'cups-browsed')

### What remains uncertain
- Exploited in wild: unknown — No positive evidence of in-the-wild exploitation in the sources checked. This is not proof that exploitation has not occurred. [KEV, CVE.ssvc]
- Conflict (stale_signal): SSVC Exploitation=poc was assessed 2024-09-27 (> 180 days ago) and may no longer reflect current activity. [CVE.ssvc]
- Offline demo uses a trimmed KEV fixture; absence was verified against the full catalogue at capture time only.
- Open question (scripted demo example): The bundle does not describe the other chained CVEs, so the difficulty of the full chain cannot be assessed from this evidence.
- Exploit-development difficulty from public evidence is inherently limited: the absence of public research does not mean exploitation is hard.

### Why this priority (rule trace)
1. Base P2: exploitation signal elevated (public exploit claimed, EPSS ≥ 0.10, or validated AI difficulty=low).
2. Exposure reduced by a documented compensating control → P3.
3. print-srv-01: compensating control (reduces_reachability): Host firewall drops inbound traffic to port 631 except from the warehouse printer VLAN — operator-supplied, not verified by this tool.

### Action supported by the evidence
- Upgrade cups-browsed 2.0.1 on print-srv-01 per the vendor advisory [NVD.ref.3].
- Verify the claimed control on print-srv-01 is in place until patched: Host firewall drops inbound traffic to port 631 except from the warehouse printer VLAN.

### What would change the recommendation
- If exploitation in the wild is reported (e.g. KEV listing) → P2
- Resolving the listed source conflicts could change the inputs above.

### AI-assisted assessment (judgement, not fact)

> **SCRIPTED EXAMPLE** — hand-written by the project author to demonstrate validation in the offline demo. It was NOT produced by a language model.

Provider `scripted`, model `scripted-example`. Claims with valid citation IDs: 7/7 (cited IDs exist, but whether the source actually says what the claim says is NOT checked). Ratings are qualitative; no calibrated probability is implied.

**Exploit-development difficulty:** `insufficient_evidence`
- *Prerequisites:* cups-browsed listens on port 631 on all interfaces and trusts packets from any source. (fact) [CVE.desc]
- *Prerequisites:* Code execution is described only when chained with other CVEs and when a user prints to the attacker's printer. (fact) [CVE.desc]
- *Complexity:* On its own this CVE is scored as integrity-low with no confidentiality or availability impact; the severe outcome depends on the chain. (inference) [CVE.cvss.1, CVE.desc]
- *Research availability:* NVD tags a researcher write-up and the vendor advisory as exploit references. (fact) [NVD.ref.1, NVD.ref.2]

**Existing-exploit usability:** `public_exploit_claimed`
- *Exploit evidence:* CISA SSVC records Exploitation=poc and Automatable=no. (fact) [CVE.ssvc]
- *Reliability limits:* Full impact requires user interaction (printing to a malicious printer), which limits automated exploitation. (inference) [CVE.desc, CVE.ssvc]
- *Required access:* Network access to port 631 on the target; no authentication. (fact) [CVE.desc, CVE.cvss.1]

*Scripted summary (uncited free text):* Network-reachable cups-browsed accepts attacker-supplied printer data; serious impact requires chaining and a user print action.

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| print-srv-01 | cups-browsed 2.0.1 | affected | [affected] CNA:GitHub_M 'cups-browsed': name 'cups browsed': matches free-text constraint '&lt;= 2.0.1' (parsed as &lt;= 2.0.1) |

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
| KEV | cisa_kev (demo) | Not listed in CISA KEV catalogue version 2026.10.08. Absence does NOT show the vulnerability is unexploited — only that CISA has not added it. | 2026-10-10T21:14:10+00:00 | 2026-10-08T20:09:18.9833Z / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 0.5060 (percentile 0.9889) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:43+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2024-47176 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok

## CVE-2024-3094 — Not applicable to the supplied inventory

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Source description (untrusted text, verbatim) [CVE.desc]:* Xz: malicious code in distributed source — Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0.  Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

**Decision:** `NOT_APPLICABLE`

**Factors:** exploitation = `elevated`, severity = `critical`, exposure = `not_affected` · **Severity-only baseline:** `P1`

### What is known (sourced facts)
- CVE record state PUBLISHED (assigner redhat, data version 5.2). [CVE.state]
- Most severe CVSS 3.1: 10.0 CRITICAL (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) from CNA:redhat [CVE.cvss.1]
- Weakness: CWE-506 [CVE.cwe, NVD.cwe]
- Kev listed: false — Not in KEV catalogue 2026.10.08 (absence is not evidence of no exploitation). [KEV]
- CISA-ADP SSVC decision points: Exploitation=none, Automatable=yes, Technical Impact=total (assessed 2024-04-02T04:00:23.138684Z). [CVE.ssvc]
- EPSS 0.8597 (percentile 0.9973) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. [EPSS]
- ops-ubuntu-02: xz 5.4.6 → not_affected [CVE.affected.1, NVD.cpe]

### What remains uncertain
- Exploited in wild: unknown — No positive evidence of in-the-wild exploitation in the sources checked. This is not proof that exploitation has not occurred. [KEV, CVE.ssvc]
- Public exploit claimed: unknown — No exploit-tagged references or SSVC PoC signal found. Exploit databases were not searched.
- Conflict (stale_signal): SSVC Exploitation=none was assessed 2024-04-02 (> 180 days ago) and may no longer reflect current activity. [CVE.ssvc]
- Offline demo uses a trimmed KEV fixture; absence was verified against the full catalogue at capture time only.
- Exploit-development difficulty from public evidence is inherently limited: the absence of public research does not mean exploitation is hard.

### Why this priority (rule trace)
1. Base P2: exploitation signal elevated (public exploit claimed, EPSS ≥ 0.10, or validated AI difficulty=low).
2. All matching inventory items are not affected → no priority.

### Action supported by the evidence
- No action for the listed assets. Keep the inventory accurate; re-assess if versions change.

### What would change the recommendation
- Resolving the listed source conflicts could change the inputs above.

### AI-assisted assessment (judgement, not fact)

Status: `not_configured` — not_configured: no scripted example for CVE-2024-3094

### Applicability details

| Asset | Software | Status | Reasons |
|---|---|---|---|
| ops-ubuntu-02 | xz 5.4.6 | not_affected | [not_affected] CNA:redhat 'xz': name 'xz': version not listed; source default status is 'unaffected'; [not_affected] NVD tukaani:xz: version 5.4.6 outside all 2 NVD ranges |

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
| KEV | cisa_kev (demo) | Not listed in CISA KEV catalogue version 2026.10.08. Absence does NOT show the vulnerability is unexploited — only that CISA has not added it. | 2026-10-10T21:14:10+00:00 | 2026-10-08T20:09:18.9833Z / - | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | first_epss (demo) | EPSS 0.8597 (percentile 0.9973) for 2026-10-10: estimated probability of exploitation activity being observed in the next 30 days. Not a difficulty or impact score. | 2026-10-10T21:13:24+00:00 | 2026-10-10 / - | https://api.first.org/data/v1/epss?cve=CVE-2024-3094 |

**Source retrieval status:** cve_org=ok; nvd=ok; cisa_kev=ok; first_epss=ok

## CVE-2026-11415 — Rejected CVE — no remediation needed

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

**Decision:** `NO_ACTION_REJECTED`

**Factors:** exploitation = `n/a`, severity = `n/a`, exposure = `n/a` · **Severity-only baseline:** `N/A`

### What is known (sourced facts)
- CVE record state REJECTED (assigner VulnCheck, data version 5.2). [CVE.state]
- Rejection reason (source text): This CVE ID has been rejected or withdrawn by its CVE Numbering Authority. [CVE.rejected]

### What remains uncertain
- Nothing flagged.

### Why this priority (rule trace)
1. Record is REJECTED → no remediation priority.

### Action supported by the evidence
- No remediation: the CVE record is rejected. Remove it from tracking and check whether the issue was re-assigned under another CVE ID [CVE.rejected].

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

**Decision:** `INVALID_OR_UNPUBLISHED`

**Factors:** exploitation = `n/a`, severity = `n/a`, exposure = `n/a` · **Severity-only baseline:** `N/A`

### What is known (sourced facts)
- CVE ID is RESERVED: assigned but no public record has been published. [CVE.state]

### What remains uncertain
- Nothing flagged.

### Why this priority (rule trace)
1. Record is reserved → nothing to assess.

### Action supported by the evidence
- Verify the CVE ID. A reserved ID has no public details yet; re-check later [CVE.state].

### What would change the recommendation
- No single input change identified.

### AI-assisted assessment (judgement, not fact)

Status: `skipped` — Not run: record is reserved.

### Evidence

| ID | Source | Summary | Retrieved | Published / updated | URL |
|---|---|---|---|---|---|
| CVE.state | cve_org (demo) | CVE ID is RESERVED: assigned but no public record has been published. | 2026-10-10T21:13:57+00:00 | - / - | https://cveawg.mitre.org/api/cve-id/CVE-2026-99001 |

**Source retrieval status:** cve_org=not_found; nvd=not_found; cisa_kev=ok; first_epss=not_found
