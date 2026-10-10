# cveprio — evidence-backed CVE prioritization assistant

A research prototype that takes a CVE ID (or a software inventory plus a CVE watch
list), collects verifiable evidence from CVE.org, NVD, CISA KEV and FIRST EPSS,
and produces an explained priority with sources, uncertainty and "what would change
this" for each recommendation.

It keeps three questions separate:

1. **Exploit-development difficulty** — how hard would a working exploit be to build? *(AI-assisted, cited)*
2. **Existing-exploit usability** — what exploits/exploitation are reported, with what limits? *(AI-assisted, checked against deterministic findings)*
3. **Organisational exposure** — is *our* deployed version affected, how reachable and important is it? *(deterministic, local only)*

The final priority comes from a **documented rule table**, not from a model-generated
score. The model can raise one factor in one narrowly defined case and is otherwise
advisory ([docs/PRIORITIZATION.md](docs/PRIORITIZATION.md)).

> **Status: working prototype, not production software.** The offline test suite
> (142 tests) and the 2 opt-in live API checks pass as of 2026-10-10, but tests do not
> establish that every security judgement is correct. See [Limitations](#limitations).

The idea of using LLMs to judge how practical exploit development is for incoming CVEs
came from a suggestion by Matthew Devost; this project extends it with evidence
provenance, applicability matching and transparent rules.

## Quick start (offline demo, no keys, no network)

```bash
git clone <this repo> && cd cve-prioritization-assistant
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cveprio demo
cveprio serve out/demo        # open http://127.0.0.1:8765/dashboard.html
```

The demo uses **recorded real API responses** (`fixtures/demo/`, captured 2026-10-10)
and a **fictional** company inventory (`examples/inventory.json`). Every output is
labelled `OFFLINE DEMO`. The AI section in the demo shows **scripted examples written
by the author** to demonstrate validation — they are labelled as such and are not model
output. Walkthrough: [docs/DEMO.md](docs/DEMO.md).

Requires Python ≥ 3.11 (developed on 3.13).

## Live use

```bash
cp .env.example .env                        # optional; edit values
cveprio check-config                        # shows effective settings, secrets masked
cveprio analyze CVE-2024-6387               # one CVE, live sources, no model
cveprio analyze --inventory examples/inventory.json            # inventory + its watchlist
cveprio analyze CVE-2024-6387 --llm ollama                     # with a local Ollama model
```

Outputs go to `out/latest/`: `report.json` (full structured data), `report.md`
(readable report), `dashboard.html` (self-contained, no network access).
Exit codes: `0` ok · `2` invalid input · `3` finished but a source failed (results are partial and say so).

### Data sources (no keys required)

| Source | Used for | Notes |
|---|---|---|
| CVE.org (CVE Services API) | record state, description, CNA/ADP affected versions, CVSS, CISA SSVC | public |
| NVD CVE API 2.0 | NVD CVSS, CPE configurations, reference tags | 5 req/30 s without key; a free [API key](https://nvd.nist.gov/developers/request-an-api-key) gives 50. *This product uses the NVD API but is not endorsed or certified by the NVD.* |
| CISA KEV | known exploitation | CC0 JSON feed |
| FIRST EPSS | 30-day exploitation-activity probability | free; attribution requested |

### Model providers (optional) — separate from Claude Code

The AI-assisted assessment is optional; everything else works without it.
**The application's model access is separate from any Claude / Claude Code
subscription you use to develop it.**

| `CVEPRIO_LLM_PROVIDER` | What you need | Cost |
|---|---|---|
| `none` (default) | nothing | free |
| `ollama` | local [Ollama](https://ollama.com) (`ollama pull qwen2.5:3b`) | free; runs on your machine |
| `openai_compatible` | any `/v1/chat/completions` server (OpenAI, vLLM, LM Studio…) | hosted endpoints bill per token |
| `anthropic` | `pip install '.[anthropic]'` and an `ANTHROPIC_API_KEY` from console.anthropic.com (pay-as-you-go API billing) | per token; see [docs/MODEL_PROVIDERS.md](docs/MODEL_PROVIDERS.md) |

Only CVE evidence is sent to a model. **Inventory, asset names, owners and business
context never leave your machine.**

## Inventory format

See [`examples/inventory.json`](examples/inventory.json). Per asset: `id`, `name`,
`software[]` (`vendor`, `product`, `version`, optional `package_name`, `cpe`), and
optional context: `criticality` (`low`…`critical`), `internet_facing`,
`compensating_controls[]`. **Missing context is treated as unknown, never as "low" or
"not exposed".** Providing a CPE (`cpe:2.3:a:vendor:product:version:...`) makes matching
against NVD much more reliable.

## How it works

```
CVE IDs ─► sources (allowlisted HTTPS, size/time limits, retries, SQLite cache)
        ─► normalize (Evidence items with IDs + provenance; findings true/false/unknown/n.a./retrieval_failed;
                      conflicts & staleness)
        ─► applicability (inventory × CNA/NVD version data → affected / not_affected / needs_review)
        ─► LLM (optional; evidence only → schema + citation validation)
        ─► rules (exploitation × severity × exposure → P1–P4 / NEEDS_REVIEW / N/A, with trace & counterfactuals)
        ─► JSON + Markdown + dashboard
```

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · rules: [docs/PRIORITIZATION.md](docs/PRIORITIZATION.md) ·
evaluation: [docs/EVALUATION.md](docs/EVALUATION.md) · plan & acceptance criteria: [docs/PLAN.md](docs/PLAN.md) ·
status: [PROGRESS.md](PROGRESS.md).

## Development

```bash
pytest                              # offline tests (fixtures + synthetic edge cases)
CVEPRIO_LIVE_TESTS=1 pytest -m live # live API checks
ruff check cveprio tests && mypy cveprio
cveprio evaluate                    # deterministic evaluation → evaluation/results/
cveprio evaluate --llm ollama       # + model-quality evaluation (local model)
cveprio capture-fixtures CVE-...    # record new offline fixtures
```

## Limitations

- **Prototype.** Not hardened, not load-tested, single-user, no authentication on `serve` (bound to 127.0.0.1).
- **Small, non-held-out evaluation** (14 cases over CVEs also used during development; reference labels drafted with AI assistance, pending review). No claim of real-world predictive accuracy.
- **Applicability is conservative and partial**: distro package versions (deb/rpm), free-text version ranges and platform-conditional NVD configurations go to `needs_review`. Vendor/product naming differs across sources; supplying CPEs helps.
- **Exploit evidence is shallow by design**: exploit-tagged references and CISA SSVC are treated as *claims*; the tool never downloads or runs exploit code and does not search exploit databases.
- **Rules have blind spots** — e.g. a supply-chain backdoor (CVE-2024-3094) with no KEV listing gets P2 on an internal asset, where a human would say P1 (documented in the evaluation).
- **Prompt-injection detection is heuristic**; the real defence is structural (data-only prompt, schema + citation validation, model cannot set priority).
- DNS-rebinding between validation and connection is not fully prevented (mitigated by the fixed host allowlist).
- Offline fixtures go stale; the KEV fixture is trimmed to the demo CVEs.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `! DEGRADED … nvd rate_limited` / exit code 3 | Wait 30 s or set `NVD_API_KEY`; results are cached in `.cache/` for 24 h. |
| AI status `failed — unavailable: cannot reach Ollama` | Start Ollama (`ollama serve`) and `ollama pull qwen2.5:3b`, or set `CVEPRIO_LLM_PROVIDER=none`. |
| AI status `failed — prompt_too_large` | Raise `CVEPRIO_LLM_NUM_CTX_MAX` (needs more RAM) — the tool refuses rather than truncating. |
| Using Ollama through `openai_compatible` gives poor results | Ollama's OpenAI endpoint silently truncates prompts longer than the server's context (default 4096). Use `--llm ollama`, or start Ollama with `OLLAMA_CONTEXT_LENGTH=16384`. |
| AI status `invalid_output` | The model returned malformed/schema-violating JSON; nothing from it is used. Try a larger model. |
| AI status `refused` (Anthropic) | A safety classifier declined; keep `CVEPRIO_ANTHROPIC_FALLBACKS=on` or run without the model. |
| Everything is `needs_review` | Add `cpe` and `vendor` to inventory items; check that versions are upstream versions, not distro package strings. |
| `skipped: no offline fixture recorded` | Offline mode only has the demo CVEs; use live mode or `cveprio capture-fixtures`. |

## Authorship and AI assistance

The project author defined the problem, scope, requirements and evaluation
expectations and directed the work. The code, tests, fixtures and documentation in
this repository were written by **Claude Code (an AI coding assistant) during a
directed session on 2026-10-10**, with the author approving decisions along the way.
The evaluation's reference judgements were drafted with AI assistance and still need
the author's independent review. Update this section as you review, modify and extend
the work.
