# Changelog

Notable changes, newest first. The project is a portfolio prototype; version numbers mark
milestones, not production releases.

## Unreleased

- **"How hard is an attack?"** on every card, for context only (it does not change the priority): the attack
  conditions from the CVE's severity score (network or local, complexity, login, user action) in plain words;
  the AI's view on building an exploit, with its reason; and, from CISA, whether attackers are already
  exploiting it or attack code is claimed, with what that does and does not show. So Log4Shell reads "easy to
  reach … attackers are already exploiting it", whatever the AI thinks.
- **The model is no longer asked what code already knows.** The attack-evidence rating (attacks
  reported / attack code claimed / none found) is set by code from CISA KEV, CISA SSVC and exploit
  references. A model rating that contradicts those facts is replaced and recorded as a correction,
  and the evaluation counts such contradictions. This fixes the small model's 0/6 miss for good.
- Prompt `2026-10-12.2`: the deterministic findings are described as reliable facts. An intermediate
  prompt (`.1`) that pushed the model to always rate difficulty was tested on held-out CVEs: it raised no
  priority, but far fewer of its claims were quote-grounded (2/10 and 3/9 vs 4/10 and 10/10), so the
  cautious "prefer insufficient evidence over guessing" guidance was kept. A Log4Shell spot check showed
  the attack rating now correct, but the small model still rates its difficulty wrongly ("high").

## 0.3.0 — 2026-10-12

**Settling "needs review" from vendors' version wording** (opt-in: `--auto-resolve`, `CVEPRIO_AUTO_RESOLVE`)
- Common wordings ("All versions prior to 26.6.5", "2.4.7 and earlier", "5.3.x prior to 5.3.18") are
  read by exact patterns in code that must match the whole sentence. This needs no AI model.
- Unusual wording can go to the configured model, under strict rules. Versions are compared in code.
  A model's reading may confirm *affected*. It can contribute to *not affected* only by showing a
  version is outside an affected range, with no conditions or open-ended wording, and only when a
  structured source independently agrees. It must keep the record's own affected/fixed status, and
  harmless slips are repaired only by widening an affected range.
- Reading the wording never overrides another source's open question (such as NVD's "only with
  Oracle JDK"), so such cases stay *needs review*.
- Results: with auto-resolve, held-out applicability 4/4 (was 3/4) and decisions 3/4 (was 2/4),
  development set unchanged, 0 unsafe answers. A development result: the feature was designed after
  held-out case h05. With qwen2.5:3b the model resolved nothing; every misreading was rejected or
  contained. Adversarial tests in `tests/test_auto_resolve.py`.

**Dashboard and reports**
- Reserved, not-found and unloadable CVEs are grouped as *Cannot assess yet* and list what is
  unknown, instead of "no action needed / nothing to do".
- A summary line reports failed or rate-limited source lookups.
- New colour-theme switch, visible keyboard focus, and a short legend separating priority, attack
  activity, severity and exposure.
- AI-raised questions and AI status are shown in plain words. Results that used a model's reading are
  labelled "AI-read wording".
- The declared-protection rule (attacked flaw → P2, not lower) is explained in reports and docs.

**Evaluation**
- Held-out set: the first 4 of 20 cases are labelled by the author, and `labels.csv` parsing tolerates
  spreadsheet output.
- Configurable model timeout (`CVEPRIO_LLM_TIMEOUT_S`); the evaluation reports why model calls failed.

**Documentation and project**
- README rebuilt around the demo, with real screenshots and a per-outcome gallery
  (`docs/SCREENSHOTS.md`). Setup and troubleshooting moved to `docs/USAGE.md`, including a
  step-by-step guide for real use and "Using Ollama safely" notes.
- MIT license. `*.local.json` is git-ignored for private inventories.

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
