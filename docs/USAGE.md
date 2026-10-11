# Using cveprio

Setup, inputs, live use and troubleshooting. For a guided tour of the offline demo see
[DEMO.md](DEMO.md); for model setup see [MODEL_PROVIDERS.md](MODEL_PROVIDERS.md).

## Install

```bash
git clone https://github.com/Be-zerk/cveprio.git
cd cveprio
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python ≥ 3.11 (CI runs 3.11, 3.12 and 3.13). Installing downloads packages from PyPI;
after that, the offline demo needs no network. For the exact dependency versions used during
development: `pip install -r requirements-lock.txt && pip install -e . --no-deps`.

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
`cveprio serve <dir>` serves a dashboard on `127.0.0.1` only.

Exit codes: `0` ok · `2` invalid input · `3` finished but a source failed (results are partial and say so).

## Data sources (no keys required)

| Source | Used for | Notes |
|---|---|---|
| CVE.org (CVE Services API) | record state, description, CNA/ADP affected versions, CVSS, CISA SSVC | public |
| NVD CVE API 2.0 | NVD CVSS, CPE configurations, reference tags | 5 req/30 s without key; a free [API key](https://nvd.nist.gov/developers/request-an-api-key) gives 50. *This product uses the NVD API but is not endorsed or certified by the NVD.* |
| CISA KEV | known exploitation | CC0 JSON feed |
| FIRST EPSS | 30-day exploitation-activity probability | free; attribution requested |
| OSV.dev | CVE discovery for packages identified by purl (`--discover`) | free, no key |
| Ubuntu CVE tracker | fixed builds per Ubuntu release, for inventory items with `"distro": "ubuntu:…"` | only the package-status fields are stored |
| Red Hat Security Data API | fixed builds per RHEL release, for items with `"distro": "rhel:…"` | CC BY 4.0; credited in every report |

## Model providers (optional)

The AI-assisted assessment is optional; everything else works without it. The
application's model access is separate from any Claude or Claude Code subscription.

| `CVEPRIO_LLM_PROVIDER` | What you need | Cost |
|---|---|---|
| `none` (default) | nothing | free |
| `ollama` | local [Ollama](https://ollama.com) (`ollama pull qwen2.5:3b`) | free; runs on your machine |
| `openai_compatible` | any `/v1/chat/completions` server (OpenAI, vLLM, LM Studio…) | hosted endpoints bill per token |
| `anthropic` | `pip install '.[anthropic]'` and an `ANTHROPIC_API_KEY` (pay-as-you-go API billing) | per token |

Only public CVE evidence is sent to a model. Inventory, asset names, owners and business
context never leave your machine. Details: [MODEL_PROVIDERS.md](MODEL_PROVIDERS.md).

## Inventory format

See [`examples/inventory.json`](../examples/inventory.json). Per asset: `id`, `name`,
`software[]` (`vendor`, `product`, `version`, optional `package_name`, `cpe`, `purl`), and
optional context: `criticality` (`low`…`critical`), `internet_facing`,
`compensating_controls[]`. **Missing context is treated as unknown, never as "low" or
"not exposed".** A CPE (`cpe:2.3:a:vendor:product:version:...`) makes matching against NVD
much more reliable, and it is what `--discover` searches with. A `purl`
(`pkg:maven/group/artifact@version`, `pkg:pypi/name@version`, …) is searched in OSV.dev.

For a package installed from a Linux distribution, give the distribution's own version string
and say which distribution it came from, for example
`{"product": "OpenSSH", "package_name": "openssh-server", "version": "1:9.6p1-3ubuntu13.4", "distro": "ubuntu:24.04", "source_package": "openssh"}`
(`rhel:9` works the same way). The tool then asks Ubuntu or Red Hat whether that build is fixed,
instead of guessing from upstream version numbers, which distributions backport fixes into.

## Using an SBOM instead of a hand-written list

An SBOM (software bill of materials) lists every library in an application with its exact
version. The tool reads **CycloneDX JSON** and **SPDX 2.x JSON**:

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
not supported.

## Finding CVEs automatically (`--discover`)

`--discover` starts from the inventory instead of a watchlist: each item with a versioned
CPE is searched in NVD, each item with a versioned purl in OSV.dev, and every CVE found
goes through the normal pipeline, where the deployed version is re-checked, so discovery
false positives end up "not applicable". The report lists every lookup, including items
that **could not be searched** because they lack a CPE/purl, and the limits of discovery.
Run against the example inventory on 2026-10-10 it found **83** candidate CVEs, versus 9 in
the hand-picked watchlist. Live only; capped by `--max-cves` (default 150, KEV-listed kept first).

## Development commands

```bash
pytest                              # offline tests (fixtures + synthetic edge cases)
CVEPRIO_LIVE_TESTS=1 pytest -m live # live API checks (network)
ruff check cveprio tests && mypy cveprio
cveprio evaluate                    # deterministic evaluation → evaluation/results/
cveprio evaluate --llm ollama       # + model-quality evaluation (local model)
cveprio evaluate --set holdout      # held-out set (labels in evaluation/holdout/labels.csv)
cveprio capture-fixtures CVE-...    # record new offline fixtures
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `! DEGRADED … nvd rate_limited` / exit code 3 | Wait 30 s or set `NVD_API_KEY`; results are cached in `.cache/` for 24 h. |
| AI status `failed — unavailable: cannot reach Ollama` | Start Ollama (`ollama serve`) and `ollama pull qwen2.5:3b`, or set `CVEPRIO_LLM_PROVIDER=none`. |
| AI status `failed — network: Ollama request timed out` | Small models on a CPU can be slow; raise `CVEPRIO_LLM_TIMEOUT_S` (default 600). |
| AI status `failed — prompt_too_large` | Raise `CVEPRIO_LLM_NUM_CTX_MAX` (needs more RAM); the tool refuses rather than truncating. |
| Using Ollama through `openai_compatible` gives poor results | Ollama's OpenAI endpoint silently truncates prompts longer than the server's context (default 4096). Use `--llm ollama`, or start Ollama with `OLLAMA_CONTEXT_LENGTH=16384`. |
| AI status `invalid_output` | The model returned malformed/schema-violating JSON; nothing from it is used. Try a larger model. |
| AI status `refused` (Anthropic) | A safety classifier declined; keep `CVEPRIO_ANTHROPIC_FALLBACKS=on` or run without the model. |
| Everything is `needs_review` | Add `cpe` and `vendor` to inventory items. For Linux packages add `"distro": "ubuntu:24.04"` (or `rhel:9`) and the distribution's version string. |
| `skipped: no offline fixture recorded` | Offline mode only has the demo CVEs; use live mode or `cveprio capture-fixtures`. |
