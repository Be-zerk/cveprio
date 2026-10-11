# Architecture

## Components

| Concern | Module | Responsibility | Does NOT |
|---|---|---|---|
| Retrieval | `net.py`, `sources/__init__.py` | Fetch CVE.org, NVD, KEV, EPSS; report an honest per-source outcome (`ok/not_found/failed/rate_limited/skipped`) | interpret security meaning |
| CVE discovery | `discovery.py`, `sources/` | Inventory → candidate CVEs via NVD CPE match and OSV purl query; reports unsearchable items and caps | decide applicability (re-checked downstream) |
| Offline fixtures | `net.FixtureFetcher`, `capture.py` | Replay recorded responses with their original retrieval times | ever touch the network |
| Normalisation | `normalize.py` | Build `Evidence` items with stable IDs and provenance; derive five-valued `Finding`s; detect conflicts and stale signals | rank or recommend |
| Applicability | `versions.py`, `applicability.py` | Decide if an inventory item is affected, conservatively | use fuzzy matches as positive evidence |
| AI analysis | `llm/` | Ask a model to interpret evidence; validate schema and citations; override contradictions | see inventory or set priority |
| Rules | `prioritize.py` | Exploitation × severity × exposure → decision, trace, counterfactuals, actions, baseline | call a model |
| Output | `report.py`, `dashboard.py`, `cli.py` | JSON, Markdown, static HTML; exit codes | hide degraded status |
| Evaluation | `evaluation.py`, `evaluation/` | Compare against reference judgements and the severity-only baseline | claim predictive accuracy |

Data types live in `models.py`. The three kinds of statement never share a type:
`Evidence` (sourced, with provenance), `Finding` (deterministic conclusion citing
evidence), and `LlmAnalysis` (AI judgement, validated, labelled).

## Key decisions (and how to defend them)

**1. The model does not produce the priority.** LLM outputs are not calibrated, can be
manipulated by text inside advisories, and are hard to audit. The priority comes from a
small rule table anyone can read and reproduce. The model's job is narrower: turn
unstructured public text into structured, *cited* observations about difficulty and
usability. Its influence on priority is limited to raising "no exploitation signal" to
"elevated" when it rates exploit development as low *with at least two cited claims*.

**2. Every claim points at evidence IDs; citations are verified in code.** IDs like
`CVE.desc`, `NVD.cvss.2`, `KEV` are stable and human-readable. Claims that cite nothing or
cite a non-existent ID are removed and counted. Ratings that contradict deterministic
findings (e.g. "exploitation reported" with no KEV/SSVC signal) are overridden and the
override is shown. **Limit:** this verifies that a cited ID exists, not that the cited
evidence actually supports the claim; testing with a small local model produced
well-cited but false statements (docs/EVALUATION.md). Ratings that *understate* the facts
are not overridden (they cannot lower priority) but are measured in the evaluation.

**3. Five-valued findings.** `true / false / unknown / not_applicable / retrieval_failed`.
"Is it in KEV?" can be `false`; "has it been exploited?" can only be `true`, `unknown` or
`retrieval_failed` — never `false`, because absence from KEV does not show absence of
exploitation. A KEV download failure is `retrieval_failed`, not "not listed".

**4. Conservative applicability.** A version is called affected/not affected only with an
exact product identity and an unambiguous comparison. Fuzzy names, distro package versions
(backports!), free-text ranges, malformed source ranges (real example: curl's CNA record
lists an empty range `[8.4.0, 8.4.0)`), and NVD "AND" configurations (Spring4Shell
requires a JDK condition) go to `needs_review`. Any ambiguous source blocks a
"not affected" conclusion; affected+not-affected from different sources is a conflict.

**5. Conservative choices under uncertainty, made visible.** CVSS disagreements use the
most severe value and are listed; unscored CVEs are not treated as low; failed
exploitation sources produce `evidence_incomplete` (base P2), not a silent downgrade;
missing business context leaves priority unchanged and marks it *provisional*.

**6. Data minimisation.** Only the public CVE evidence bundle is sent to a model. Exposure
is computed locally from the inventory. A test asserts that asset IDs, names, owners,
organisation name and criticality never appear in any prompt.

**7. Separate live and demo paths.** `SafeFetcher` never falls back to fixtures and
`FixtureFetcher` never falls back to the network. Demo results are labelled in CLI output,
JSON (`mode`, `evidence[].demo`), Markdown and the dashboard. Scripted AI examples are
labelled "SCRIPTED EXAMPLE — not produced by a language model".

**8. Few dependencies, no services.** `pydantic` (typed models + validation), `httpx`
(timeouts, streaming size limits, mock transports for tests), `packaging` (PEP 440),
`jinja2` (autoescaped HTML). SQLite (stdlib) for the cache. The optional `anthropic` SDK
for Claude. No database server, queue or web framework.

## CVE discovery (stage 6)

A hand-picked watchlist silently misses CVEs (the demo inventory's Log4j 2.14.1 is affected
by at least 10 CVEs per NVD; the watchlist had 1). `--discover` derives candidates from the
inventory: versioned CPE 2.3 → NVD `virtualMatchString`; versioned purl → OSV `/v1/query`
(CVE IDs from `id` or `aliases`; non-CVE advisories counted, not analysed). Results are
unioned with a "found by" note per CVE. Discovery is deliberately *recall-oriented*: it may
return CVEs where the item is only a platform (e.g. a product that runs on Spring), and the
applicability engine filters those (`NOT_IN_INVENTORY`). Nothing is silently skipped: items
without identifiers, failed lookups, truncated result sets and the cap all appear in the report.

## Retrieval safety

- HTTPS only; hosts restricted to `cveawg.mitre.org`, `services.nvd.nist.gov`,
  `api.first.org`, `www.cisa.gov`, `api.osv.dev` (POST JSON queries only for OSV). No user-supplied or retrieved URL is ever fetched
  (reference URLs are shown as links, never requested).
- Every resolved IP must be global: loopback, RFC1918, link-local (incl. cloud metadata
  `169.254.169.254`), CGNAT, ULA and multicast are refused.
- No automatic redirects; each hop re-validated; max 3.
- Streaming size limits per source (KEV 16 MB, NVD 4 MB, others ≤ 2 MB); 30 s timeouts.
- Bounded retries (3 attempts) for 429/5xx/timeouts; `Retry-After` honoured up to 30 s;
  NVD's 403 throttling treated as rate limiting; per-host request spacing (NVD 6.5 s
  without key, 0.7 s with key).
- JSON parsing failures are source failures, not empty results.
- The NVD API key is sent as a header, so it is not part of the cache key or stored.
- Known gap: DNS could change between validation and connection (rebinding); the fixed
  allowlist of public government/FIRST hosts limits the impact.

## Prompt-injection handling

Retrieved text is untrusted. Defences, from strongest to weakest:

1. **The model cannot set priority or statuses.** Even an obedient model only produces
   ratings that are re-checked (test: `test_priority_invariant_even_when_detector_misses`).
2. **Schema validation** (`extra="forbid"`): no extra fields such as a smuggled `risk_score`.
3. **Citation validation** and **rating overrides** against deterministic findings.
4. **Data-only prompt**: evidence is JSON-encoded with `<`/`>` escaped inside one
   delimited block, so text cannot close the block or fake tags.
5. **Heuristic detector** flags instruction-like phrases for the reader. It is
   deliberately not relied on; tests show phrasing it misses.

The dashboard renders all text through Jinja2 autoescaping, only `http(s)` links are
emitted, and a CSP (`default-src 'none'`) stops the page making network requests.

## Report contract

Every CVE report (JSON and Markdown) contains: decision label + priority + provisional
flag, factors, severity-only baseline, **what is known** (cited), **what remains
uncertain**, **rule trace**, **supported actions**, **counterfactuals** ("what would
change it", computed by re-running the rules with one input changed), the AI section
(status, kept/removed claims, overrides), applicability details, and the evidence table
(source, URL, retrieval time, published/updated dates).
