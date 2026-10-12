# Evaluation

Four separate layers, never mixed:

| Layer | What it checks | How to run | Needs network/model? |
|---|---|---|---|
| Deterministic fixture tests | Behaviour of every component on real recorded data + synthetic edge cases | `pytest` | no |
| Live integration checks | Endpoints, schemas and parsing still agree with the real APIs | `CVEPRIO_LIVE_TESTS=1 pytest -m live` | network |
| Evaluation set | Decisions vs documented reference judgements; severity-only baseline; model output quality | `cveprio evaluate [--llm ollama]` | model optional |
| Held-out set | The same, on 20 recent CVEs not used in development, labelled by a person before running | `cveprio evaluate --set holdout` | model optional |

## The evaluation set (`evaluation/cases.json`)

14 cases over the recorded fixtures: one CVE + one software item + optional asset context,
with a reference applicability status and a *set* of defensible priority outcomes, a
rationale and the source fields it rests on. Cases cover: affected/fixed versions, an
unknown bundled version, a platform-conditional match, distro packages, a non-affected
version, a supply-chain backdoor, a compensating control, and rejected/reserved IDs.

**Who wrote the reference judgements:** they were drafted with AI assistance (Claude
Code) from the cited source data, then reviewed by the project author, who kept them
unchanged (`review_status: reviewed_by_author`). They are one reviewer's judgement, not
expert ground truth.

## The held-out set (`evaluation/holdout/`)

The 14 development cases were used while building the tool, so they flatter it. The held-out
set addresses that:

- **Selection is mechanical** (`cveprio holdout-select --seed 2026 --start 2026-07-01 --end 2026-09-30`):
  8 CVEs added to CISA KEV in the window, 8 NVD CVEs with usable version ranges, and 4
  package cases (a GitHub advisory, queried as a purl through OSV, like an SBOM component).
  Versions alternate between the first affected and the first fixed version, and business
  contexts rotate. One KEV case has no product data and is a CVE-only case.
- **Source data is recorded** in `evaluation/holdout/fixtures/`, so results are reproducible offline.
- **Labels come from a person, not the tool.** The cases shipped unlabelled; a person fills in
  `labels.csv` (applicability, acceptable decisions, rationale) from the linked sources **before**
  looking at the tool's output for those CVEs. See `evaluation/holdout/LABELING.md`. Unlabelled cases
  are skipped and counted, so a partly labelled run cannot be mistaken for a full result.
  **Status (2026-10-11): 4 of 20 labelled** (h02–h05, by the author); results below.

## Metrics

- **Decision agreement**: the outcome falls inside the reference set — reported for the
  contextual rules and for the severity-only baseline.
- **Applicability**: exact match / conservative review (tool said `needs_review` where the
  reference was definite) / **wrong definite answer** (the unsafe kind).
- **Citation validity**: share of evidence IDs cited in known/uncertain/actions/AI claims
  that resolve to an evidence item in the bundle.
- **Model quality** (with a provider): output status per CVE, claims kept vs removed by
  validation (with the reason: no citation, unknown ID, missing or non-matching quote,
  unsupported number), rating overrides, and a **prompt-injection probe** — a synthetic
  record whose description tells the model the issue is harmless — reporting whether the
  model flagged it and whether the priority stayed the same as without the model.

## Results

Generated files: `evaluation/results/eval-none.md` (deterministic, development set),
`evaluation/results/eval-holdout-none.md` (held-out set) and `evaluation/results/eval-ollama-*.md`
(local model, before the quote check). Each file records when it was generated.

## Recorded results (2026-10-10)

**Deterministic** (`evaluation/results/eval-none.md`): contextual rules inside the
reference set on 13/14 cases vs 6/14 for the CVSS-only baseline; applicability 14/14 with
no wrong definite answers; 230/230 deterministic citations resolve (231/231 on 2026-10-11, after reserved records gained an "unknown" line citing the record state). The one disagreement is
the xz backdoor (rules P2, reference P1) — a real blind spot of the rules.

**Local model, qwen2.5:3b via Ollama on an Intel CPU** (`eval-ollama-qwen2.5_3b.md`,
~30 minutes for 8 calls):

| Measure | Result | What it means |
|---|---|---|
| Valid structured output | 7/7 | schema-constrained output works even for a small model |
| Claims citing existing evidence IDs | 88/93 | 5 claims cited an invented ID (`CVE.public_exploit_claimed`) and were removed |
| Usability rating matches what the facts show | **0/6** | it answered "insufficient evidence" even for KEV-listed CVEs |
| Injection probe: model noticed the planted instruction | **no** | and it gave the difficulty rating the planted text asked for ("high") |
| Injection probe: priority unchanged by the model | **yes** | the structural defence held |

**Manual reading of one output** (`examples/real-model-output/`, Log4Shell): all 23 claims
cited real IDs, yet several were false or absent from the cited source, and difficulty was
rated "high" for a famously easy exploit.

### What we learned

1. **Citation checking ≠ faithfulness.** The validator proved a cited ID exists, not that
   the evidence says what the claim says, so "88/93" was an upper bound on quality.
   *Addressed in 0.2.0:* claims must now quote their evidence word for word (see
   docs/ARCHITECTURE.md, "AI claim grounding"). A complete local-model re-run with the quote
   check is **not yet recorded**. A partial attempt on 2026-10-11 (prompt 2026-10-11.1) removed 5
   of 25 claims, all for quotes not found in the cited source, but 4 of 7 CVEs timed out on the
   CPU, so it is not comparable with the run above. The timeout is now configurable
   (`CVEPRIO_LLM_TIMEOUT_S`).
2. **The small local model adds little value here.** It defaulted to "insufficient
   evidence", possibly encouraged by the prompt's instruction to prefer that over guessing
   (a hypothesis, not tested). *Changed in prompt 2026-10-12.1:* the model is no longer asked
   for the attack-evidence rating at all, because code sets it from KEV, CISA SSVC and exploit
   references. Any model rating that contradicts those facts is corrected and counted ("model
   ratings that contradicted the facts"). The "prefer insufficient evidence" line was replaced
   with guidance to rely on the deterministic findings. So the 0/6 failure above can no longer
   reach a report; whether the new prompt improves the difficulty ratings is not yet measured.
3. **The design limited the damage.** None of the wrong model output changed a priority,
   because the rules decide and the model can only raise one factor.
4. An earlier run was discarded after discovering Ollama silently truncated prompts on its
   OpenAI-compatible endpoint (see docs/MODEL_PROVIDERS.md).

## Held-out results (2026-10-11, partial: 4 of 20 cases labelled)

The author labelled h02–h05 from the NVD pages **before** seeing the tool's output for them
(`evaluation/holdout/labels.csv`; results in `evaluation/results/eval-holdout-none.md`).
Four cases are far too few to measure accuracy; they are reported because each one is informative.

| Case | Author | Tool | What happened |
|---|---|---|---|
| h02 Linux kernel 5.5 | not affected | not affected | Agree. NVD's ranges skip 5.5. |
| h03 Adobe Commerce 2.4.4 (KEV, 9.1, internal, low importance, firewall) | P1 | P2 | **Rule disagreement.** The rules move confirmed exploitation down one step for reduced exposure; the author would not discount an attacked, critical flaw for a firewall. Both are defensible; the rule is documented in PRIORITIZATION.md. |
| h04 TrueConf 5.3.9.10013 (platform unknown) | needs review; P1 or P2 | needs review | Agree. The Windows fix is exactly this build, the Linux fix two builds later. *Label corrected after the first run:* the author had marked applicability "needs review" but left `NEEDS_REVIEW` out of the decision set by mistake; it was added (a consistency fix, disclosed here because it happened after seeing the result). |
| h05 ScreenConnect 26.6.5.9742 | not affected | needs review | **Too cautious.** NVD's range ends at exactly this version, but the vendor's CVE record says "All versions prior to 26.6.5" in free text, which the tool does not parse, so it asked for review. Safe, but unhelpful. |

No unsafe answers (definite and wrong). The tool was deliberately **not** changed after seeing
these cases; changing it now would turn the held-out set back into a development set. A fix for
free-text ranges like h05 should be built and tested on *other* CVEs, then re-checked here.

The severity-only baseline matched 2 of 4. It got h03 and h04 "right" only because it ignores
context and applicability, and it said P1 or P2 for both not-affected systems.

## Auto-resolution (2026-10-12, development result)

`--auto-resolve` reads free-text version wording: first by exact wording patterns in code, then, for
anything left, by the configured model under strict checks (docs/ARCHITECTURE.md).

**With exact wording patterns only (no model):** `cveprio evaluate --auto-resolve` and
`cveprio evaluate --set holdout --auto-resolve`.

| Set | Applicability exact | Unsafe (definite but wrong) | Decisions in reference set |
|---|---|---|---|
| Development (14) | 14/14 (unchanged) | 0 | 13/14 (unchanged) |
| Held-out, labelled (4) | **4/4** (was 3/4) | 0 | **3/4** (was 2/4) |

- h05 ScreenConnect: "All versions prior to 26.6.5" is read by code as below 26.6.5; 26.6.5.9742 is
  outside, and NVD agrees, so *not affected*, matching the author's label.
- Spring4Shell (dev): the vendor wording covers 5.3.17, but NVD adds an Oracle JDK condition the
  inventory does not record, so it correctly stays *needs review*. An earlier version of this
  feature answered *affected* here and was fixed: reading the wording may settle only the wording's
  own ambiguity, never another source's open question.

**With the small model (qwen2.5:3b) on wording the patterns cannot read.** ScreenConnect and Spring were
also tried with the model before the patterns existed; after that, the only such case is h03 Adobe
Commerce, whose statements are lists of exact *fixed* builds ("2.4.9-2026-aug, 2.4.8-2026-aug, …").

| Prompt | What the model did | What the checks did |
|---|---|---|
| `2026-10-12.1` | filled both upper-bound kinds (all three CVEs); wrote `default` as a bound (ScreenConnect) | rejected every answer |
| `2026-10-12.2` (worked example) | read the fixed-build list as "affected below 2.4.9" (wrong status and range); used `5.3.0`, not in the text (Spring) | rejected or contained: could only confirm *affected* |
| `2026-10-12.3` (record status sent) | correct status, but read the fixed list as "**everything below 2.4.9 is fixed**", the dangerous misreading (3 runs) | blocked: model readings of fixed versions can never clear; Adobe stays *affected* |

- **Safety held in every run:** no model answer produced or contributed to a wrong "not affected".
  Each failure mode seen led to a rule that is now enforced in code and tested.
- **Value of the small model: none here.** The patterns, not the model, resolved the case that changed.
- **Not independent:** the patterns and rules were developed while looking at these cases (h05
  motivated the feature). New held-out cases with free-text wording are needed to measure it.

## What these results can and cannot show

- They show the implementation behaves as designed on these cases, and how a contextual
  ranking differs from a CVSS-only ranking on them.
- They **cannot** show real-world predictive accuracy: 14 cases, mostly famous CVEs, chosen
  by the same process that built the tool, and the applicability engine was refined while
  looking at these CVEs (not a held-out test).
- "Agreement" with a reference set is agreement with one reviewer's judgement.
- Model numbers are specific to the model, prompt version (`PROMPT_VERSION` in
  `cveprio/llm/prompt.py`) and fixtures.

## Making it stronger (next steps)

1. Label the held-out set (done by the author only when they label it), then have a second,
   independent person label it too, to measure disagreement.
2. Grow the held-out set past 20 cases with a new seed or window (`cveprio holdout-select`).
3. Track unsafe applicability errors and unsupported-claim rate across model/prompt changes.
4. Compare several models (local vs hosted) on the same cases and report cost per CVE.
