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
Code) from the cited source data and are pending the author's independent review
(`review_status` in the file). They are not expert ground truth.

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
