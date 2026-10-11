# Progress and handoff

_Last updated: 2026-10-10 (end of first build session)._

## Starting state

Empty directory `~/Projects/cve-prioritization-assistant`, created for this project at
the author's request. A separate earlier repository on this machine was deliberately not
used ("disregard the other repo"); nothing was copied from it.

## Completed (all five planned stages)

| Stage | Status | Evidence |
|---|---|---|
| 1. One CVE → complete source-backed report | done | `cveprio analyze CVE-2021-44228 --offline`; `tests/test_evidence.py` |
| 2. Multiple CVEs + inventory | done | `cveprio demo`; `tests/test_applicability.py`, `tests/test_pipeline.py` |
| 3. Business context in prioritization | done | `tests/test_prioritize.py::test_business_context_changes_priority` |
| 4. Dashboard | done | `out/demo/dashboard.html`; inspected in a browser at desktop and 375 px, light and dark |
| 5. Evaluation, docs, demo | done | `evaluation/results/`, `docs/`, `README.md` |
| 7. SBOM import (CycloneDX / SPDX 2.x JSON) | done | `--sbom`, `examples/inventory-sbom.json`; `tests/test_sbom.py`; real SBOM of this project scanned (0 known CVEs) |
| 6. CVE discovery + disputed records (added after reviewing the demo) | done | `cveprio analyze --inventory examples/inventory.json --discover` → 83 CVEs; `tests/test_discovery.py` |

Acceptance criteria AC1–AC31 are in [docs/PLAN.md](docs/PLAN.md); the assessment against
them is at the end of this file.

## What was run (2026-10-10)

- `pytest`: **185 passed, 3 skipped** (the 3 live tests are opt-in).
- `CVEPRIO_LIVE_TESTS=1 pytest -m live`: **3 passed** against the real CVE.org, NVD, KEV, EPSS and OSV APIs (incl. discovery).
- `ruff check cveprio tests`: clean. `mypy cveprio`: clean.
- `cveprio demo`: completes offline, exit code 0.
- Live end-to-end: `cveprio analyze CVE-2024-3400 CVE-2023-4966 --inventory examples/inventory.json` → exit 0, all sources `ok`.
- `cveprio evaluate` (deterministic): rules 13/14 within reference set vs baseline 6/14.
- `cveprio evaluate --llm ollama` (qwen2.5:3b, local, ~30 min): 7/7 valid outputs, 88/93 claims with
  valid citation IDs, but usability matched the facts 0/6 and the model did not notice the
  injection probe; priority unchanged by the model. A manual read found well-cited false claims.
  An earlier run was discarded because Ollama silently truncated prompts.

## Not tested / blockers

- **Anthropic provider never called live** — no `ANTHROPIC_API_KEY` was available. Only the
  missing-key path is tested. Needs: an API key from console.anthropic.com (paid), then
  `cveprio analyze CVE-2024-6387 --offline --llm anthropic`. The server-side fallback beta
  parameter is unverified.
- **No hosted OpenAI-compatible endpoint tested** (only mocked transports, plus local Ollama
  through its OpenAI endpoint, where truncation was discovered).
- **Reference judgements** in `evaluation/cases.json` were drafted with AI assistance and
  reviewed by the author (no cases changed).
- Git: the repository is initialised but **nothing has been committed** (no commit was requested).

## Known issues / limitations

- **Highest-priority improvement:** check that cited evidence actually supports each AI claim
  (faithfulness), not just that the ID exists. Then retest with a stronger model and a
  revised prompt on the same evaluation.

See README "Limitations". The most important: the evaluation set is small and not held
out; the rules under-rank a supply-chain backdoor without KEV listing; distro package
versions always require review; prompt-injection detection is heuristic only.

## Exact next step

The author has reviewed the evaluation reference judgements (no cases changed) and has run
the demo, configured an NVD API key and run a live inventory analysis on their own machine.
Next: build the claim-faithfulness check (verify that cited evidence actually supports each
AI claim), then re-run `cveprio evaluate --llm ollama` and compare against the recorded results.

Suggested follow-ups after that: distro advisory sources (Ubuntu USN / Red Hat CSAF) to
resolve `needs_review` for package versions; NVD CPE-based CVE discovery from an inventory
(no watchlist); a held-out evaluation set of recent CVEs labelled before running the tool.

## Acceptance criteria assessment

| AC | Met? | How verified |
|---|---|---|
| AC1 provenance on evidence | yes | `test_every_evidence_item_has_provenance` |
| AC2 invalid IDs before network | yes | `test_invalid_ids_rejected_before_network`, CLI exit 2 |
| AC3 unknown/reserved/rejected | yes | real fixtures: `test_rejected_record`, `test_reserved_id…`, `test_nonexistent_id` |
| AC4 source statuses + five-valued findings | yes | `models.Truth`, `test_kev_retrieval_failure…`, `test_both_record_sources_down…` |
| AC5 KEV absence ≠ safe | yes | `test_kev_absence_is_not_proof_of_no_exploitation` |
| AC6 conflicts & staleness | yes | real CVSS conflict (curl), stale SSVC (xz), synthetic KEV-vs-SSVC |
| AC7 exploit refs are claims | yes | `test_exploit_tagged_reference_is_a_claim_not_verification` |
| AC8 exact identity + unambiguous version | yes | applicability tests (log4j, xz, OpenSSH upstream) |
| AC9 ambiguity → review | yes | distro version, fuzzy name, AND config, malformed range, disagreement tests |
| AC10 schema-invalid output → status | yes | `test_unparseable_output…`, `test_schema_violation_rejected` |
| AC11 citations validated | partly — IDs verified to exist; claim faithfulness not verified | `test_unsupported_and_fabricated_citations_removed` |
| AC12 injection handled structurally | yes | `test_injected_text_is_escaped…`, `test_priority_invariant_even_when_detector_misses`, eval probe |
| AC13 inventory not sent to model | yes | `test_inventory_and_context_never_sent_to_model` |
| AC14 no confidence-as-probability | yes | schema has no numeric fields; `test_assessment_schema_has_no_numeric_confidence` |
| AC15 rule trace | yes | `test_rule_table` (every decision has a trace) |
| AC16 no invented context | yes | `test_missing_context_is_provisional…`, `test_partial_context…` |
| AC17 report sections | yes | `test_every_report_has_required_sections` |
| AC18 baseline | yes | `test_baseline_is_severity_only`; dashboard comparison panel |
| AC19 URL/IP/size/time/retry limits | yes | `tests/test_net.py` (24 tests) |
| AC20 visible degradation | yes | `test_degraded_run_is_visible_not_filled_in`, exit code 3, Ollama truncation guard |
| AC21 demo labelled | yes | `test_demo_clearly_labelled_everywhere` |
| AC22 no secrets | yes | `test_cli_demo_writes_outputs_and_no_secrets`, repo scan test, masked `Settings` |
| AC23 evaluation report | yes | `evaluation/results/eval-*.md` |
| AC25 discovery from inventory | yes | `test_discover_merges_sources…`, live `test_live_discovery_finds_known_log4j_cves` |
| AC26 nothing silently skipped | yes | `not_searchable` rows, cap/failed caveats; `test_discover_merges_sources…` |
| AC27 discovered CVEs re-checked | yes | live run: CVE-2023-44794 (Spring-based product) → `NOT_IN_INVENTORY` |
| AC28 disputed records | yes | `test_disputed_tag_flagged_but_priority_not_lowered`, `test_dispute_wording_in_description_detected` |
| AC29 SBOM formats | yes | `test_real_cyclonedx_from_official_tool`, `test_spdx_purl_cpe_supplier_and_missing_version`, `test_bad_sbom_files_rejected_clearly` |
| AC30 skipped components reported | yes | `test_cyclonedx_skips_non_software_and_reports_it`, `test_oversized_sbom_refused` |
| AC31 no invented context | yes | `test_inventory_from_sboms_uses_supplied_context_only` |
| AC24 new-user walkthrough | mostly | the author ran the demo, set an NVD key and ran a live inventory analysis following the docs; configuring a model provider themselves is not yet done |
