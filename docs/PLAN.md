# Implementation plan and acceptance criteria

Written before the core logic was implemented (2026-10-10). Status is tracked in
[`PROGRESS.md`](../PROGRESS.md); this file records what we set out to build and
how we decide whether it works.

## Objective

An evidence-backed assistant that takes a CVE ID (or a software inventory plus a
CVE watch list), collects verifiable evidence from authoritative sources, keeps
three assessments separate (exploit-development difficulty, existing-exploit
usability, organisational exposure), and produces a priority recommendation from
**documented deterministic rules**. The LLM is used only to interpret public text
into structured, citation-checked observations; it never sets the priority.

## Verified source facts (checked live on 2026-10-10)

| Source | Endpoint | Auth | Notes |
|---|---|---|---|
| CVE Program (CVE Services) | `https://cveawg.mitre.org/api/cve/{id}` | none | CVE JSON 5.x. 404 `CVE_RECORD_DNE` for unknown IDs. `cveMetadata.state` is `PUBLISHED`/`REJECTED`. Reserved IDs are only visible via `/api/cve-id/{id}` (`state: RESERVED`). Containers: `cna` + `adp` (CISA-ADP "Vulnrichment" carries SSVC `Exploitation: none/poc/active` with a timestamp, plus CVSS when the CNA gave none). |
| NVD CVE API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=` | optional `apiKey` header | 5 req/30 s without key, 50 with. Fields used: `vulnStatus`, `metrics.cvssMetricV31/V40/V30/V2` (with `source` + `type`), `configurations` (CPE match ranges), `references[].tags` ("Exploit"), `cisaExploitAdd`. Required notice: *"This product uses the NVD API but is not endorsed or certified by the NVD."* |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | none | CC0. ~1.8 MB full catalogue; `catalogVersion`, `dateReleased`, per-entry `dateAdded`, `knownRansomwareCampaignUse`, `requiredAction`, `dueDate`. Inclusion = exploited in the wild; absence is **not** evidence of non-exploitation. |
| FIRST EPSS | `https://api.first.org/data/v1/epss?cve=a,b` | none | Free, attribution requested. Probability of observed exploitation activity in the **next 30 days**; percentile is relative rank. Not a difficulty score, not a complete risk score. CVEs with no score are simply absent from `data`. |

## Architecture (components kept separate)

| Concern | Module |
|---|---|
| Source retrieval, URL safety, limits, retries, caching | `cveprio/net.py`, `cveprio/sources/*` |
| Evidence normalisation + provenance, conflict/staleness detection | `cveprio/normalize.py` |
| Product/version applicability | `cveprio/versions.py`, `cveprio/applicability.py` |
| LLM-assisted analysis (schema + evidence-ID validation) | `cveprio/llm/*` |
| Transparent prioritisation rules + severity-only baseline | `cveprio/prioritize.py` |
| Reports (JSON/Markdown), dashboard, CLI | `cveprio/report.py`, `cveprio/dashboard.py`, `cveprio/cli.py` |
| Evaluation | `cveprio/evaluation.py`, `evaluation/` |

## Stages

1. One CVE → complete source-backed JSON + Markdown report (offline fixtures and live).
2. Multiple CVEs and an inventory (assets × CVE watch list) with applicability matching.
3. Business context (criticality, internet exposure, compensating controls) changes priority via documented rules.
4. Static dashboard exposing evidence, uncertainty and recommendations.
5. Evaluation (fixture tests, model-quality eval, baseline comparison), docs, demo walkthrough.

## Acceptance criteria

Each criterion maps to at least one automated test (see `tests/`) unless marked *manual*.

**Evidence and provenance**
- AC1 Every evidence item records source name, URL, retrieval time, and the structured fields/excerpt it rests on; publication/update dates when the source provides them.
- AC2 Invalid CVE ID syntax is rejected before any network call.
- AC3 Unknown (404), reserved, and rejected CVEs produce explicit statuses and an appropriate non-remediation recommendation — never a fabricated analysis.
- AC4 Each source's outcome is one of `ok`, `not_found`, `failed`, `rate_limited`, `skipped`, and each fact distinguishes **true / false / unknown / not applicable / retrieval failed**.
- AC5 KEV absence is reported as "not listed (absence ≠ no exploitation)"; if KEV retrieval failed it is "retrieval failed", not "not listed".
- AC6 Conflicting CVSS scores between sources and stale exploitation signals (e.g. SSVC `none` older than a threshold, or contradicted by KEV) are surfaced as conflicts/warnings.
- AC7 Exploit-tagged references are reported as *claims of public exploit material*, never as verified working exploits.

**Applicability**
- AC8 A deployed version is marked `affected`/`not_affected` only when product identity matches exactly (normalised vendor+product, package name, or CPE) and the version comparison is unambiguous.
- AC9 Fuzzy product similarity, free-text version ranges, unparseable/distro-patched versions, or conflicting sources yield `needs_review`, with the reason.

**LLM analysis**
- AC10 Model output is validated against a schema; invalid JSON or schema violations produce an `llm_failed` status, not invented content.
- AC11 Every model claim must cite evidence IDs that exist in the bundle; unsupported claims are removed and counted.
- AC12 Retrieved text is passed as delimited, untrusted data; injection-like text is flagged, and model output cannot change priority, statuses or citations beyond the schema.
- AC13 Inventory and business context are not sent to the model.
- AC14 Model self-reported confidence is not displayed as a probability.

**Prioritisation and reports**
- AC15 Priority comes from a documented rule table; every report includes the rule trace.
- AC16 With no business context, exposure is `unknown` and the report says so; nothing is invented.
- AC17 Every report contains: what is known, what is uncertain, why this priority, supported action, and what would change the recommendation.
- AC18 A severity-only baseline is computed alongside for comparison.

**Reliability and security**
- AC19 Only allowlisted HTTPS hosts are fetched; private/loopback/link-local addresses are refused; responses are size-limited; timeouts and bounded retries (honouring `Retry-After`, capped) are enforced.
- AC20 Source failures and rate limits degrade visibly (partial results flagged), never silently replaced with fixture data.
- AC21 Offline demo mode is visibly labelled in CLI output, JSON, Markdown and dashboard.
- AC22 No secrets in code, fixtures, logs or reports; `.env.example` contains placeholders only.

**Evaluation and delivery**
- AC23 Evaluation reports priority agreement with documented reference judgements for both the contextual rules and the severity-only baseline, plus applicability errors, citation validity and unsupported-claim counts; it states the set is too small to claim predictive accuracy.
- AC24 A new user can follow the README to run the offline demo, configure live sources/model, and inspect evidence (*manual walkthrough*).
