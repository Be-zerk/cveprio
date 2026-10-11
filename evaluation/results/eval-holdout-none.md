# Evaluation results (none)

Generated 2026-10-11T22:00:31Z on the recorded fixtures (offline).

> HELD-OUT evaluation set, selected mechanically by `cveprio holdout-select` (see cveprio/holdout.py) with seed 2026 from CVEs dated 2026-07-01 to 2026-09-30. None of these CVEs were used while building the tool. Expected answers must be filled in by a human labeller from the linked sources BEFORE running `cveprio evaluate --set holdout`; see LABELING.md.

**16 cases have no expected answers yet and were skipped.** Fill them in before reading anything into these numbers.

## Deterministic results

| Metric | Value |
|---|---|
| Cases | 4 |
| Contextual rules within reference set | 2/4 |
| Severity-only baseline within reference set | 2/4 |
| Applicability exact match | 3/4 |
| Applicability: review where reference was definite (conservative) | 1 |
| Applicability: definite but wrong (unsafe) | 0 |
| Deterministic citations resolving to evidence | 54/54 |

| Case | CVE | Applicability (exp → got) | Reference set | Contextual | Baseline |
|---|---|---|---|---|---|
| h02 | CVE-2026-53266 | not_affected → not_affected (match) | NOT_APPLICABLE | NOT_APPLICABLE ✓ | P2 ✗ |
| h03 | CVE-2026-71362 | affected → affected (match) | P1 | P2 ✗ | P1 ✓ |
| h04 | CVE-2026-72529 | needs_review → needs_review (match) | NEEDS_REVIEW, P1, P2 | NEEDS_REVIEW ✓ | P1 ✓ |
| h05 | CVE-2026-84869 | not_affected → needs_review (conservative_review) | NOT_APPLICABLE | NEEDS_REVIEW ✗ | P1 ✗ |

### Where the rules disagree with the reference

- **h03**: rules gave `P2`; reference ['P1']. affected and 9.1 score
- **h05**: rules gave `NEEDS_REVIEW`; reference ['NOT_APPLICABLE']. NVD: fixed in 26.6.5.9742 (up to excluding), which is the installed version

## Model-quality results

No model provider was used for this run (deterministic only).

## Limitations

- 4 labelled cases picked mechanically from recent CVEs (seeded random sample); a small sample, so one case moves the percentages a lot.
- Labels come from one person (the project author) reading the public sources; there is no second labeller, so disagreements between reasonable analysts are not measured.
- The fixtures were recorded once; NVD and vendors often add product data weeks after publication, so some 'needs review' results may reflect data that was missing at capture time.
- 'Agreement' means the outcome is inside a set the reviewer considers defensible, not that it is correct.
- Claim checks confirm the cited evidence exists, contains the claim's quote word for word and any numbers/dates it mentions. That is grounding, not proof the reasoning is right: a model can quote real text and still draw a wrong conclusion from it.
- Model-quality numbers depend on the model, prompt version and fixtures; rerun after any change.
