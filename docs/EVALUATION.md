# Evaluation

Three separate layers, never mixed:

| Layer | What it checks | How to run | Needs network/model? |
|---|---|---|---|
| Deterministic fixture tests | Behaviour of every component on real recorded data + synthetic edge cases | `pytest` | no |
| Live integration checks | Endpoints, schemas and parsing still agree with the real APIs | `CVEPRIO_LIVE_TESTS=1 pytest -m live` | network |
| Evaluation set | Decisions vs documented reference judgements; severity-only baseline; model output quality | `cveprio evaluate [--llm ollama]` | model optional |

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

## Metrics

- **Decision agreement**: the outcome falls inside the reference set — reported for the
  contextual rules and for the severity-only baseline.
- **Applicability**: exact match / conservative review (tool said `needs_review` where the
  reference was definite) / **wrong definite answer** (the unsafe kind).
- **Citation validity**: share of evidence IDs cited in known/uncertain/actions/AI claims
  that resolve to an evidence item in the bundle.
- **Model quality** (with a provider): output status per CVE, claims kept vs removed by
  citation validation, rating overrides, and a **prompt-injection probe** — a synthetic
  record whose description tells the model the issue is harmless — reporting whether the
  model flagged it and whether the priority stayed the same as without the model.

## Results

Generated files: `evaluation/results/eval-none.md` (deterministic) and
`evaluation/results/eval-ollama-*.md` (local model). Summary of the 2026-10-10 runs is in
the "Recorded results" section below.

## Recorded results (2026-10-10)

**Deterministic** (`evaluation/results/eval-none.md`): contextual rules inside the
reference set on 13/14 cases vs 6/14 for the CVSS-only baseline; applicability 14/14 with
no wrong definite answers; 230/230 deterministic citations resolve. The one disagreement is
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

1. **Citation checking ≠ faithfulness.** The validator proves a cited ID exists, not that
   the evidence says what the claim says. "88/93" is therefore an upper bound on quality.
   Checking entailment (e.g. a second model, or quoting the exact supporting text and
   string-matching it) is the most important next improvement.
2. **The small local model adds little value here.** It defaulted to "insufficient
   evidence", possibly encouraged by the prompt's instruction to prefer that over guessing
   (a hypothesis, not tested). A larger model and a revised prompt should be compared on
   this same evaluation.
3. **The design limited the damage.** None of the wrong model output changed a priority,
   because the rules decide and the model can only raise one factor.
4. An earlier run was discarded after discovering Ollama silently truncated prompts on its
   OpenAI-compatible endpoint (see docs/MODEL_PROVIDERS.md).

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

1. Have an independent reviewer label cases **before** running the tool on them.
2. Add ≥ 30 recent CVEs (not famous, mixed outcomes), captured with `cveprio capture-fixtures`.
3. Track unsafe applicability errors and unsupported-claim rate across model/prompt changes.
4. Compare several models (local vs hosted) on the same cases and report cost per CVE.
