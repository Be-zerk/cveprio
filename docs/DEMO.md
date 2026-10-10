# Demonstration walkthrough (≈ 10 minutes)

Everything here runs offline from recorded fixtures. Outputs are labelled
`OFFLINE DEMO`; the company (Northbeam Logistics) and its assets are fictional.

## 1. Run it

```bash
source .venv/bin/activate
cveprio demo
cveprio serve out/demo     # http://127.0.0.1:8765/dashboard.html
```

Expected terminal summary (the `*` marks provisional decisions):

```
CVE                DECISION                 BASELINE  EXPLOITATION         SEVERITY  EXPOSURE
CVE-2021-44228     P1                       P1        confirmed            critical  high
CVE-2023-44487     P1                       P2        confirmed            high      high
CVE-2024-6387      P1                       P2        elevated             high      high
CVE-2023-38545     P2*                      P1        elevated             critical  context_unknown
CVE-2022-22965     NEEDS_REVIEW*            P1        confirmed            critical  needs_review
CVE-2024-47176     P3                       P3        elevated             medium    reduced
CVE-2024-3094      NOT_APPLICABLE           P1        elevated             critical  not_affected
CVE-2026-11415     NO_ACTION_REJECTED       N/A       n/a                  n/a       n/a
CVE-2026-99001     INVALID_OR_UNPUBLISHED   N/A       n/a                  n/a       n/a
```

## 2. Talking points, one CVE each

| CVE | What to show | Point it makes |
|---|---|---|
| CVE-2023-44487 (HTTP/2 Rapid Reset) | CVSS-only says P2; rules say P1 | KEV listing + internet-facing nginx outranks a "high" CVSS |
| CVE-2024-3094 (xz backdoor) | CVSS 10 → baseline P1; tool says NOT_APPLICABLE | The deployed xz 5.4.6 is outside the affected versions (two sources agree). Context removes noise |
| CVE-2023-38545 (curl SOCKS5) | NVD 9.8 vs CISA-ADP 8.8 conflict; P2 *provisional* | Conflicts are shown, not hidden; dev laptop has no context → provisional, not assumed low |
| CVE-2022-22965 (Spring4Shell) | NEEDS_REVIEW "would be P1 if affected" | NVD's configuration requires a JDK condition the inventory doesn't record; the tool asks instead of guessing |
| CVE-2024-6387 (regreSSHion) | Expand → applicability table | Upstream 9.6p1 on the bastion is affected; the Ubuntu package `1:9.6p1-3ubuntu13.4` is `needs_review` (backports) |
| CVE-2024-6387 | AI section (scripted) | Validation removed a claim citing `NVD.ref.99` (doesn't exist), removed an uncited claim, and overrode "exploitation_reported" because nothing reports exploitation |
| CVE-2024-47176 (cups-browsed) | Exposure `reduced` | An operator-declared firewall control lowers P2 → P3, labelled "not verified by this tool" |
| CVE-2026-11415 / 99001 | Rejected / reserved | Explicit non-remediation outcomes; no analysis invented |

In each expanded card, walk through: **What is known** (each line has evidence IDs) →
**Evidence** table (source URL, retrieval time, dates) → **Why this priority** (rule
trace) → **What would change** (counterfactuals) → **Uncertain**.

## 3. Show the failure handling

```bash
cveprio analyze CVE-21-1 --offline           # invalid ID → exit 2, no network call
cveprio analyze CVE-2020-0001 --offline      # not in fixtures → sources "skipped", decision RETRIEVAL_FAILED
CVEPRIO_OLLAMA_URL=http://localhost:9 cveprio analyze CVE-2024-6387 --offline --llm ollama
                                             # model unreachable → AI status "failed", rest of report intact
```

## 4. Optional: a real model, locally

```bash
ollama pull qwen2.5:3b
cveprio analyze CVE-2024-6387 CVE-2024-47176 --offline --llm ollama --out out/ollama
```

This produces genuine model output (labelled with the model name). Compare how many
claims survive validation with the scripted example. Saved results from a run during
development are in `evaluation/results/`.

## 5. Optional: live data

```bash
cveprio analyze CVE-2024-3400 --inventory examples/inventory.json --out out/live
```

Live results are labelled `mode: live`, cached for 24 h in `.cache/`, and will differ from
the fixtures as sources update.
