# Progress and handoff

_Last updated: 2026-10-11._

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
| 8. Quote-grounded AI claims, Ubuntu/Red Hat advisories, held-out set (0.2.0) | done, except labelling | `tests/test_llm.py`, `tests/test_distro*.py`, `tests/test_holdout.py`; demo OpenSSH on Ubuntu 24.04 now `not_affected`; `evaluation/holdout/` (20 cases, unlabelled) |

Acceptance criteria AC1–AC34 are in [docs/PLAN.md](docs/PLAN.md); the assessment against
them is at the end of this file.

## What was run (latest: 2026-10-11, version 0.2.0)

- `pytest`: **233 passed, 3 skipped** (the 3 live tests are opt-in).
- `CVEPRIO_LIVE_TESTS=1 pytest -m live`: **3 passed** against the real CVE.org, NVD, KEV, EPSS and OSV APIs (incl. discovery).
- `cveprio holdout-select`: 20 cases selected and their source data recorded (Ubuntu's API often returned HTTP 504 and needed retries).
- `cveprio evaluate --set holdout`: runs; all 20 cases skipped as unlabelled, as intended.
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

## Known issues / limitations

- **The held-out set is unlabelled.** Until a person fills in `evaluation/holdout/labels.csv`,
  the tool has no measured accuracy on CVEs it was not built around.
- AI claims are now quote-grounded, but a real quote can still support a wrong conclusion.

See README "Limitations". Also important: the rules under-rank a supply-chain backdoor without
a KEV listing; distribution packages are only resolved for Ubuntu and RHEL; prompt-injection
detection is heuristic only.

## Exact next step

The author has reviewed the evaluation reference judgements (no cases changed) and has run
the demo, configured an NVD API key and run a live inventory analysis on their own machine.
Version 0.2.0 added quote-grounded AI claims, Ubuntu/Red Hat advisories and the held-out set
(see CHANGELOG.md).

**Next: the author labels the held-out set** by following `evaluation/holdout/LABELING.md`
*before* looking at the tool's output for those CVEs. Then run `cveprio evaluate --set holdout`
and record the results in docs/EVALUATION.md. After that: a second labeller; a stronger model
compared on the same cases; Debian/SUSE/Alpine advisories.

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
| AC11 citations validated | yes — IDs exist and a verbatim quote from the cited evidence is required (grounding, not entailment) | `test_unsupported_and_fabricated_citations_removed`, `test_claim_with_fabricated_quote_is_removed` |
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
| AC32 quote-grounded claims | yes | `test_claim_with_fabricated_quote_is_removed`, `test_claim_without_quote_is_removed`, `test_claim_mentioning_numbers_missing_from_source_is_removed` |
| AC33 distro advisories | yes | `test_ubuntu_verdicts`, `test_redhat_verdicts`, `test_without_distro_data_it_stays_needs_review`, `test_compare_deb`, `test_compare_rpm` |
| AC34 held-out set | yes (labels pending, by design) | `test_committed_holdout_is_unlabelled`, `test_unlabelled_cases_are_skipped_and_labels_csv_is_used` |
| AC24 new-user walkthrough | mostly | the author ran the demo, set an NVD key and ran a live inventory analysis following the docs; configuring a model provider themselves is not yet done |
