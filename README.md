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
> (185 tests) and the 3 opt-in live API checks pass as of 2026-10-10, but tests do not
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

The demo's CVE watchlist is **hand-picked** to show every kind of outcome; it is not a
complete list of the CVEs affecting that inventory (live `--discover` finds those).
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
cveprio analyze --inventory examples/inventory.json            # inventory + its (hand-picked) watchlist
cveprio analyze --inventory examples/inventory.json --discover # find CVEs from the software list itself
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
| OSV.dev | CVE discovery for packages identified by purl (`--discover`) | free, no key |

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
against NVD much more reliable, and it is what `--discover` searches with. Add a
`purl` (`pkg:maven/group/artifact@version`, `pkg:pypi/name@version`, …) to also search OSV.dev.

### Using an SBOM instead of a hand-written list

An SBOM (software bill of materials) is the "ingredients list" of an application: every
library with its exact version. Build tools produce them automatically. cveprio reads
**CycloneDX JSON** and **SPDX 2.x JSON**:

```bash
# one application from an SBOM file, with business context on the command line
cveprio analyze --sbom my-app.cdx.json --criticality high --internet-facing yes --discover

# or keep business context in an inventory and point each asset at its SBOM
cveprio analyze --inventory examples/inventory-sbom.json --discover
```

To make an SBOM of a Python environment: `pip install cyclonedx-bom` then
`cyclonedx-py environment --of JSON -o sbom.cdx.json`. (`examples/sbom/cveprio-python-env.cdx.json`
is this project's own SBOM made that way; scanning it found no known vulnerabilities on 2026-10-10.)
Components without a version, non-software entries and anything over the limits are listed
as skipped. SBOM components are matched mainly by package URL (purl) through OSV.dev, whose
"this exact version is affected" answer is recorded as evidence. CycloneDX XML and SPDX 3 are
not supported yet.

### Finding CVEs automatically (`--discover`)

`--discover` starts from the inventory instead of a watchlist: each item with a versioned
CPE is searched in NVD, each item with a versioned purl in OSV.dev, and every CVE found
goes through the normal pipeline (where the deployed version is re-checked, so discovery
false positives end up "not applicable"). The report lists every lookup, including items
that **could not be searched** because they lack a CPE/purl, and the limits of discovery.
Run against the example inventory on 2026-10-10 it found **83** candidate CVEs, versus 9 in
the hand-picked watchlist. Live only; capped by `--max-cves` (default 150, KEV-listed kept first).

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
- **Small, non-held-out evaluation** (14 cases over CVEs also used during development; reference labels drafted with AI assistance and reviewed by the author). No claim of real-world predictive accuracy.
- **SBOM support** covers CycloneDX JSON and SPDX 2.x JSON only; SBOM quality limits results (missing versions or purls mean components cannot be searched).
- **Discovery is only as complete as the identifiers**: items without a CPE/purl are not searched (reported), a product listed under several CPE names (curl vs libcurl) may be missed, and vendor/distribution advisories are not searched.
- **Disputed CVEs** are flagged (structured tags, or dispute wording in the description — heuristic) but their priority is not lowered automatically.
- **Applicability is conservative and partial**: distro package versions (deb/rpm), free-text version ranges and platform-conditional NVD configurations go to `needs_review`. Vendor/product naming differs across sources; supplying CPEs helps.
- **Exploit evidence is shallow by design**: exploit-tagged references and CISA SSVC are treated as *claims*; the tool never downloads or runs exploit code and does not search exploit databases.
- **Rules have blind spots** — e.g. a supply-chain backdoor (CVE-2024-3094) with no KEV listing gets P2 on an internal asset, where a human would say P1 (documented in the evaluation).
- **AI claims are citation-checked, not fact-checked**: the tool verifies cited evidence IDs exist, not that the source says what the claim says. A small local model (qwen2.5:3b) produced well-cited but wrong statements and missed obvious exploitation evidence (0/6); treat AI notes as leads to verify.
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
The evaluation's reference judgements were drafted with AI assistance and then
reviewed by the author. Update this section as you review, modify and extend
the work.
