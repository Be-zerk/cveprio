# CVE prioritization report

Generated 2026-10-10T22:16:50+00:00 · mode **offline_demo** · cveprio 0.1.0

> OFFLINE DEMO MODE: data comes from recorded fixtures (see retrieval times), not live sources. Results may be out of date.
> This product uses the NVD API but is not endorsed or certified by the NVD.
> CVE records: CVE Program (cve.org). KEV: CISA Known Exploited Vulnerabilities catalogue (CC0). EPSS: FIRST.org Exploit Prediction Scoring System (https://www.first.org/epss).

| CVE | Decision | Baseline (CVSS only) | Exploitation | Severity | Exposure |
|---|---|---|---|---|---|
| CVE-2021-44228 | P1 (provisional) | P1 | confirmed | critical | not_assessed |

## CVE-2021-44228 — P1: Act now: emergency change / out-of-band patching (provisional)

> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.

*Source description (untrusted text, verbatim) [CVE.desc]:* Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints — Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that t

**Decision:** `P1` · priority P1 · provisional

**Factors:** exploitation = `confirmed`, severity = `critical`, exposure = `not_assessed` · **Severity-only baseline:** `P1`

**In short:** Attackers are known to be using it: it is on CISA's list of actively attacked flaws (added 2021-12-10), and CISA rates exploitation as active. No software list was given, so it is unknown whether you run the affected product.

### What is known (sourced facts)
- CVE status: Published (active) — assigned by apache; published 2021-12-10; last updated 2025-10-21 [CVE.state]
- Severity: 10.0 / 10 (Critical) — CVSS 3.1 score from CISA; 3 sources agree. Full breakdown in Severity score details. [CVE.cvss.1]
- Type of flaw: Improper Input Validation (+3 more) — CWE-20: Improper Input Validation; CWE-400: Uncontrolled Resource Consumption; CWE-502: Deserialization of Untrusted Data; CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection'). CWE = MITRE's Common Weakness Enumeration. [CVE.cwe, NVD.cwe]
- On the US government's list of actively attacked flaws (KEV): Yes — Listed in the CISA Known Exploited Vulnerabilities catalogue. [KEV]
- Known to be exploited by attackers: Yes — Positive evidence of exploitation in the wild (KEV listing and/or CISA SSVC Exploitation=active). [KEV, CVE.ssvc]
- Attack code reported to be public: Yes — 12 source item(s) indicate public exploit/PoC material. Existence, reliability and impact of that code are NOT verified by this tool. [CVE.ssvc, NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, NVD.ref.11, NVD.ref.14, NVD.ref.15]
- CISA's rating: attacks have been seen — CISA SSVC decision points: Exploitation=active, Automatable=yes, Technical Impact=total; assessed 2025-02-04. [CVE.ssvc]
- Predicted chance of attacks in the next 30 days: >99.9% — EPSS 1.0000, higher than 100.0% of all scored CVEs, scored 2026-10-10 (FIRST EPSS model). Estimates exploitation activity, not difficulty or impact. [EPSS]

### What remains uncertain
- We don't know if you run this software — No inventory or business context was supplied, so whether this CVE affects you, and how exposed that system is, is unknown (not assumed).
- Open question: What specific versions of Apache Log4j2 are known to be vulnerable… — What specific versions of Apache Log4j2 are known to be vulnerable and how can they be identified? (Source: raised by the AI assessment; not verified.)
- Open question: What specific configurations of Apache Log4j2 are known to be… — What specific configurations of Apache Log4j2 are known to be vulnerable and how can they be identified? (Source: raised by the AI assessment; not verified.)
- Open question: What specific types of log messages or log message parameters are… — What specific types of log messages or log message parameters are known to be vulnerable and how can they be identified? (Source: raised by the AI assessment; not verified.)
- Open question: What specific versions of Apache Log4j2 are known to be vulnerable… — What specific versions of Apache Log4j2 are known to be vulnerable and how can they be identified? (Source: raised by the AI assessment; not verified.)
- Open question: What specific configurations of Apache Log4j2 are known to be… — What specific configurations of Apache Log4j2 are known to be vulnerable and how can they be identified? (Source: raised by the AI assessment; not verified.)
- Open question: What specific types of log messages or log message parameters are… — What specific types of log messages or log message parameters are known to be vulnerable and how can they be identified? (Source: raised by the AI assessment; not verified.)

### Why this priority (rule trace)
1. Starts at P1: attackers are known to be using it — exploitation confirmed by the CISA KEV list and/or CISA SSVC Exploitation=active.
2. Provisional: only applies if you run this software — No inventory supplied; the priority applies only if the product is deployed.

### Action supported by the evidence
- Find out whether you run an affected version — supply an inventory to automate this; if you do, remediate. [NVD.ref.9, NVD.ref.10, NVD.ref.12]
- Follow CISA's official instructions for this flaw — quoted source text: For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available. [KEV]

### What would change the recommendation
- If you don't run an affected version → no action needed — no affected product/version is deployed

### AI-assisted assessment (judgement, not fact)

Provider `ollama`, model `qwen2.5:3b`. Claims with valid citation IDs: 23/23 (cited IDs exist, but whether the source actually says what the claim says is NOT checked). Ratings are qualitative; no calibrated probability is implied.

**Exploit-development difficulty:** `high`
- *Prerequisites:* Understanding of Java and Apache Log4j2 (fact) [CVE.desc]
- *Prerequisites:* Knowledge of JNDI (Java Naming and Directory Interface) and LDAP protocols (fact) [CVE.desc]
- *Prerequisites:* Ability to craft and manipulate Java properties files (fact) [CVE.desc]
- *Prerequisites:* Familiarity with the Apache Log4j2 configuration and logging mechanisms (fact) [CVE.desc]
- *Complexity:* The vulnerability is specific to the JNDI features of Apache Log4j2, which are not widely used in production environments. (fact) [CVE.desc]
- *Complexity:* The vulnerability requires a specific configuration of the Apache Log4j2 library, which may not be present in all affected environments. (fact) [CVE.desc]
- *Complexity:* The vulnerability requires a specific type of log message or log message parameter to be controlled by an attacker, which may not be present in all affected environments. (fact) [CVE.desc]
- *Complexity:* The vulnerability requires the use of a JNDI-related endpoint, which may not be present in all affected environments. (fact) [CVE.desc]
- *Complexity:* The vulnerability requires the use of a specific version of Apache Log4j2, which may not be present in all affected environments. (fact) [CVE.affected.1]
- *Research availability:* Public research exists on the vulnerability, including details on the specific configuration and log message requirements. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8]
- *Research availability:* Public research exists on the specific JNDI-related endpoint and how to manipulate it to exploit the vulnerability. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8]
- *Research availability:* Public research exists on the specific version of Apache Log4j2 that is vulnerable and how to identify it. (fact) [CVE.affected.1]

**Existing-exploit usability:** `insufficient_evidence`
- *Exploit evidence:* Public exploit material exists, but the reliability and impact of that code are NOT verified by this tool. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, CVE.ssvc]
- *Exploit evidence:* Public exploit material exists, but the specific versions of Apache Log4j2 that are vulnerable are not specified. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, CVE.ssvc]
- *Exploit evidence:* Public exploit material exists, but the specific configurations of Apache Log4j2 that are vulnerable are not specified. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, CVE.ssvc]
- *Exploit evidence:* Public exploit material exists, but the specific types of log messages or log message parameters that are vulnerable are not specified. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, CVE.ssvc]
- *Reliability limits:* The reliability of the public exploit material is unknown. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, CVE.ssvc]
- *Reliability limits:* The specific versions of Apache Log4j2 that are vulnerable are not specified, making it difficult to verify the exploit against a given deployment. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, CVE.ssvc]
- *Reliability limits:* The specific configurations of Apache Log4j2 that are vulnerable are not specified, making it difficult to verify the exploit against a given deployment. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, CVE.ssvc]
- *Reliability limits:* The specific types of log messages or log message parameters that are vulnerable are not specified, making it difficult to verify the exploit against a given deployment. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, CVE.ssvc]
- *Required access:* The exploit requires access to the Apache Log4j2 library and configuration files. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, CVE.ssvc]
- *Required access:* The exploit requires the ability to manipulate the Apache Log4j2 configuration files to include the vulnerable JNDI-related endpoint. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, CVE.ssvc]
- *Required access:* The exploit requires the ability to control the log messages or log message parameters to include the vulnerable JNDI-related endpoint. (fact) [NVD.ref.1, NVD.ref.2, NVD.ref.3, NVD.ref.4, NVD.ref.5, NVD.ref.6, NVD.ref.7, NVD.ref.8, CVE.ssvc]

*Model summary (uncited free text):* The vulnerability is specific to the JNDI features of Apache Log4j2, which are not widely used in production environments. Public research exists on the specific configuration and log message requirements, as well as the specific JNDI-related endpoint and how to manipulate it to exploit the vulnerability. However, the reliability of the public exploit material is unknown, and the specific versions of Apache Log4j2 that are vulnerable, as well as the specific configurations and types of log messages or log message parameters that are vulnerable, are not specified. The exploit requires access to the Apache Log4j2 library and configuration files, as well as the ability to manipulate the configuration files and control the log messages or log message parameters.

### Severity score details

| Source | CVSS version | Score | Rating | Evidence |
|---|---|---|---|---|
| CISA **(used)** | 3.1 | 10.0 | Critical | CVE.cvss.1 |
| NVD | 3.1 | 10.0 | Critical | NVD.cvss.1 |
| another scoring organisation | 3.1 | 10.0 | Critical | NVD.cvss.2 |
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
