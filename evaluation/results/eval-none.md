# Evaluation results (none)

Generated 2026-10-12T02:02:04Z on the recorded fixtures (offline).

> Small evaluation set over the recorded fixtures in fixtures/demo. Each case pairs one CVE with one software item and (optionally) asset context, plus a reference judgement: the applicability status a careful analyst should reach from the cited source fields, and the set of priority outcomes the reference reviewer considers defensible. Reference judgements were DRAFTED WITH AI ASSISTANCE (Claude Code) from the cited source data and then REVIEWED BY THE PROJECT AUTHOR, who kept them unchanged; they are one reviewer's judgement, not expert ground truth. 14 cases cannot support claims about real-world predictive accuracy.

## Deterministic results

| Metric | Value |
|---|---|
| Cases | 14 |
| Contextual rules within reference set | 13/14 |
| Severity-only baseline within reference set | 6/14 |
| Applicability exact match | 14/14 |
| Applicability: review where reference was definite (conservative) | 0 |
| Applicability: definite but wrong (unsafe) | 0 |
| Deterministic citations resolving to evidence | 231/231 |

| Case | CVE | Applicability (exp → got) | Reference set | Contextual | Baseline |
|---|---|---|---|---|---|
| log4j-exposed | CVE-2021-44228 | affected → affected (match) | P1 | P1 ✓ | P1 ✓ |
| log4j-fixed | CVE-2021-44228 | not_affected → not_affected (match) | NOT_APPLICABLE | NOT_APPLICABLE ✓ | P1 ✗ |
| log4j-bundled-unknown | CVE-2021-44228 | needs_review → needs_review (match) | NEEDS_REVIEW | NEEDS_REVIEW ✓ | P1 ✗ |
| spring4shell-jdk-unknown | CVE-2022-22965 | needs_review → needs_review (match) | NEEDS_REVIEW, P1 | NEEDS_REVIEW ✓ | P1 ✓ |
| rapid-reset-edge | CVE-2023-44487 | affected → affected (match) | P1 | P1 ✓ | P2 ✗ |
| rapid-reset-internal-low | CVE-2023-44487 | affected → affected (match) | P1, P2 | P1 ✓ | P2 ✓ |
| regresshion-upstream | CVE-2024-6387 | affected → affected (match) | P1, P2 | P1 ✓ | P2 ✓ |
| regresshion-ubuntu-package | CVE-2024-6387 | needs_review → needs_review (match) | NEEDS_REVIEW | NEEDS_REVIEW ✓ | P2 ✗ |
| xz-unaffected | CVE-2024-3094 | not_affected → not_affected (match) | NOT_APPLICABLE | NOT_APPLICABLE ✓ | P1 ✗ |
| xz-backdoored-internal | CVE-2024-3094 | affected → affected (match) | P1 | P2 ✗ | P1 ✓ |
| curl-internal | CVE-2023-38545 | affected → affected (match) | P2, P3 | P2 ✓ | P1 ✗ |
| cups-firewalled | CVE-2024-47176 | affected → affected (match) | P3, P4 | P3 ✓ | P3 ✓ |
| rejected-id | CVE-2026-11415 | no_product_match → no_product_match (match) | NO_ACTION_REJECTED | NO_ACTION_REJECTED ✓ | N/A ✗ |
| reserved-id | CVE-2026-99001 | no_product_match → no_product_match (match) | INVALID_OR_UNPUBLISHED | INVALID_OR_UNPUBLISHED ✓ | N/A ✗ |

### Where the rules disagree with the reference

- **xz-backdoored-internal**: rules gave `P2`; reference ['P1']. A deliberately backdoored release of a core library: reviewer judgement is to remove it immediately regardless of exposure. This is expected to DISAGREE with the rules (which give P2: no KEV, internal medium asset) and documents a known limitation: the rules have no notion of 'supply-chain compromise'.

## Model-quality results

No model provider was used for this run (deterministic only).

## Limitations

- 14 hand-picked, mostly well-known CVEs; results say nothing about accuracy on new or obscure CVEs.
- NOT a held-out test: these CVEs were also used while building the applicability engine, so applicability scores here are optimistic. See `cveprio evaluate --set holdout` for the held-out set.
- The severity-only baseline has no notion of rejected/reserved records, so it cannot match those cases.
- Reference judgements were drafted with AI assistance and reviewed by the project author (one reviewer).
- 'Agreement' means the outcome is inside a set the reviewer considers defensible, not that it is correct.
- Claim checks confirm the cited evidence exists, contains the claim's quote word for word and any numbers/dates it mentions. That is grounding, not proof the reasoning is right: a model can quote real text and still draw a wrong conclusion from it.
- Model-quality numbers depend on the model, prompt version and fixtures; rerun after any change.
