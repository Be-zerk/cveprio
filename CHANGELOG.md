# Changelog

Notable changes, newest first. The project is a portfolio prototype; version numbers mark
milestones, not production releases.

## 0.2.0 — 2026-10-11

**More trustworthy AI output**
- Every AI claim must now include a short quote copied word for word from the evidence it cites.
  Claims whose quote is missing or cannot be found in that evidence are removed. Claims that mention
  a version, number or date the cited evidence does not contain are also removed. The removal reason
  is shown in the report ("What the checker removed"). Prompt version `2026-10-11.1`.

**Fewer "needs review" results for Linux packages**
- Ubuntu and Red Hat security advisories are fetched for inventory items that name a distribution
  (`"distro": "ubuntu:24.04"` / `"rhel:9"`, or a `pkg:deb`/`pkg:rpm` purl). A distribution package
  is judged by the distribution's own fixed build, using Debian and RPM version comparison, instead
  of upstream version ranges. Example: the demo's OpenSSH 1:9.6p1-3ubuntu13.4 is now
  *not affected* by CVE-2024-6387, where it was *needs review* before.

**A fairer test set**
- `cveprio holdout-select` mechanically picks 20 CVEs from July to September 2026 that were never
  used during development (8 known-exploited, 8 high-severity, 4 package/SBOM cases) and records
  their source data offline. They ship **unlabelled**: a person fills in `labels.csv` from the
  sources before running `cveprio evaluate --set holdout`. Unlabelled cases are skipped and counted.

**Finding and reading CVEs** (since 0.1.0)
- `--discover` finds CVEs for an inventory through NVD CPE matching and OSV.dev package queries.
- SBOM import: CycloneDX JSON and SPDX 2.x JSON (`--sbom`).
- Disputed CVE records are detected and flagged.
- Reports and the dashboard explain each decision in plain, CVE-specific language. Specialist
  details (CVSS vectors, raw descriptions, evidence) are kept in collapsible sections.

**Rule changes** (details in `docs/PRIORITIZATION.md`)
- A single unverified "exploit" link no longer counts as confirmed exploitation. It becomes
  *claimed, unverified*.
- High exposure moves a CVE up one step, but reaches P1 only with confirmed exploitation or
  high/critical severity. Low-severity CVEs are capped at P3 unless exploitation is confirmed or
  evidence is missing.

**Engineering**
- GitHub Actions CI (ruff, mypy, pytest, offline demo on Python 3.11 to 3.13); pinned
  `requirements-lock.txt`.

## 0.1.0 — 2026-10-10

First working version (stages 1 to 5 of `docs/PLAN.md`):
- Evidence retrieval from CVE.org, NVD, CISA KEV and FIRST EPSS through an allowlisted, size-limited
  and cached HTTPS client.
- Conservative version applicability against an inventory.
- Rule-based priority (P1 to P4, plus needs review and not applicable). An optional AI model can only
  add cited analysis; it never sets the priority.
- Schema- and citation-checked AI output: Anthropic API, local Ollama, or a scripted offline demo.
- Markdown/JSON reports, a static HTML dashboard, and an offline demo built from recorded data.
- An evaluation on 14 development cases against a severity-only baseline.
