# Demonstration walkthrough (≈ 10 minutes)

Everything here runs offline from recorded fixtures. The 9 CVEs are a **hand-picked**
watchlist chosen to show every outcome — not the full set of CVEs affecting the fictional
company's software (e.g. its Log4j version has several more). Say this when presenting. Outputs are labelled
`OFFLINE DEMO`; the company (Northbeam Logistics) and its assets are fictional.

## 1. Run it

```bash
source .venv/bin/activate
cveprio demo
cveprio serve out/demo     # http://127.0.0.1:8765/dashboard.html
```

Expected terminal summary (the `*` marks provisional decisions):

```
CVE                DECISION               SCORE ALONE  ATTACKS                                EXPOSURE
CVE-2021-44228     P1 fix now             P1           attacked (CISA list since 2021-12-10)  web-portal-01 is internet-facing and high importance
CVE-2023-44487     P1 fix now             P2           attacked (CISA list since 2023-10-10)  web-portal-01 is internet-facing and high importance
CVE-2024-6387      P1 fix now             P2           demo attack code exists (CISA)         bastion-01 is internet-facing and high importance
CVE-2023-38545     P2 next patch cycle*   P1           demo attack code exists (CISA)         dev-laptop-17: internet exposure and importance not recorded (+1 more s…
CVE-2022-22965     needs review*          P1           attacked (CISA list since 2022-04-04)  Unclear whether web-portal-01 is affected
CVE-2024-47176     P3 schedule a fix      P3           demo attack code exists (CISA)         print-srv-01 is protected by a declared control (not verified)
CVE-2024-3094      not affected           P1           attacks likely (86.0% in 30 days)      your version is not affected
CVE-2026-11415     cancelled CVE          -            -                                      -
CVE-2026-99001     no details yet         -            -                                      -
  * provisional: depends on information that was not supplied
```

## 2. Talking points, one CVE each

| CVE | What to show | Point it makes |
|---|---|---|
| CVE-2023-44487 (HTTP/2 Rapid Reset) | Score alone says P2; tool says P1 | KEV listing + internet-facing nginx outranks a "high" CVSS |
| CVE-2024-3094 (xz backdoor) | CVSS 10 → score alone says P1; tool says "Not affected" | The deployed xz 5.4.6 is outside the affected versions (two sources agree). Context removes noise |
| CVE-2023-38545 (curl SOCKS5) | NVD 9.8 vs CISA-ADP 8.8 conflict; P2 *provisional* | Conflicts are shown, not hidden; dev laptop has no context → provisional, not assumed low |
| CVE-2022-22965 (Spring4Shell) | NEEDS_REVIEW "would be P1 if affected" | NVD's configuration requires a JDK condition the inventory doesn't record; the tool asks instead of guessing |
| CVE-2024-6387 (regreSSHion) | Expand → applicability table | Upstream 9.6p1 on the bastion is affected; the Ubuntu package `1:9.6p1-3ubuntu13.4` is *not affected*, because Ubuntu's advisory says it was fixed in `…13.3` (distributions backport fixes) |
| CVE-2024-6387 | AI section (scripted) | Validation removed a claim citing `NVD.ref.99` (doesn't exist), a claim whose quote ("under a minute") is not in the cited evidence, and an uncited claim, and overrode "exploitation_reported" because nothing reports exploitation |
| CVE-2024-47176 (cups-browsed) | Exposure `reduced` | An operator-declared firewall control lowers P2 → P3, labelled "not verified by this tool" |
| CVE-2026-11415 / 99001 | Rejected / reserved | A rejected CVE needs no fix; a reserved one is *Cannot assess yet* (nothing is known, which is not the same as safe). No analysis invented |

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

## 5. Live discovery: from software list to CVEs

```bash
cveprio analyze --inventory examples/inventory.json --discover --out out/discover
```

Instead of the hand-picked list, this searches NVD and OSV for every inventory item that
has a CPE or purl. On 2026-10-10 it found 83 candidate CVEs (about a minute with an NVD key).
Point out: the discovery table lists items that could **not** be searched (no identifier),
a Spring-based product found by discovery is filtered as `NOT_IN_INVENTORY`, and
CVE-2016-1000027 is flagged as disputed without being deprioritised.

## 6. Optional: live data

```bash
cveprio analyze CVE-2024-3400 --inventory examples/inventory.json --out out/live
```

Live results are labelled `mode: live`, cached for 24 h in `.cache/`, and will differ from
the fixtures as sources update.
