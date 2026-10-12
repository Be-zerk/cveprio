# Architecture

## Components

| Concern | Module | Responsibility | Does NOT |
|---|---|---|---|
| Retrieval | `net.py`, `sources/__init__.py` | Fetch CVE.org, NVD, KEV, EPSS, OSV, Ubuntu and Red Hat advisories; report an honest per-source outcome (`ok/not_found/failed/rate_limited/skipped`) | interpret security meaning |
| SBOM import | `sbom.py` | CycloneDX / SPDX 2.x JSON → inventory software items; limits, skipped-component reporting | fetch anything referenced in the SBOM |
| CVE discovery | `discovery.py`, `sources/` | Inventory → candidate CVEs via NVD CPE match and OSV purl query; reports unsearchable items and caps | decide applicability (re-checked downstream) |
| Offline fixtures | `net.FixtureFetcher`, `capture.py` | Replay recorded responses with their original retrieval times | ever touch the network |
| Normalisation | `normalize.py` | Build `Evidence` items with stable IDs and provenance; derive five-valued `Finding`s; detect conflicts and stale signals | rank or recommend |
| Applicability | `versions.py`, `applicability.py` | Decide if an inventory item is affected, conservatively; distro packages are judged by the distro's advisory (deb/rpm version comparison) | use fuzzy matches as positive evidence |
| AI analysis | `llm/` | Ask a model to interpret evidence; validate schema, citations and verbatim quotes; override contradictions | see inventory or set priority |
| Rules | `prioritize.py` | Exploitation × severity × exposure → decision, trace, counterfactuals, actions, baseline | call a model |
| Output | `report.py`, `dashboard.py`, `cli.py` | JSON, Markdown, static HTML; exit codes | hide degraded status |
| Evaluation | `evaluation.py`, `evaluation/` | Compare against reference judgements and the severity-only baseline; select the held-out set (`holdout.py`) | claim predictive accuracy |

Data types live in `models.py`. The three kinds of statement never share a type:
`Evidence` (sourced, with provenance), `Finding` (deterministic conclusion citing
evidence), and `LlmAnalysis` (AI judgement, validated, labelled).

## Key decisions (and how to defend them)

**1. The model does not produce the priority.** LLM outputs are not calibrated, can be
manipulated by text inside advisories, and are hard to audit. The priority comes from a
small rule table anyone can read and reproduce. The model's job is narrower: turn
unstructured public text into structured, *cited* observations about difficulty and
usability. Its influence on priority is limited to one rule input: when there is no strong
exploitation signal (`low_observed` or `claimed_unverified`), a validated rating of "low"
exploit-development difficulty with at least two claims that passed validation raises
exploitation to `elevated`. That can move a CVE up (to P2, or P1 with high exposure and
high/critical severity); it can never lower one. A prompt injection that talks a model into
"low difficulty" could therefore raise a priority. That is the accepted failure direction.
With `--auto-resolve`, the model may also read free-text version statements (see "AI reading of
version statements" below); that path is designed so an AI reading alone can never clear a system.

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

## SBOM import (stage 7)

`sbom.py` turns CycloneDX (`components[]`, nested) or SPDX 2.x (`packages[]`, `externalRefs`
purl / cpe23Type) into software items. Field names were checked against a real cyclonedx-py 7.5
output and the official SPDX 2.3 JSON schema. The SBOM is untrusted input (25 MB, 5,000
components, trimmed strings, nothing fetched). Because SBOM components are usually identified
by purl rather than vendor/product names, OSV's per-version answer is stored as an `OSV.n`
evidence item and accepted by the applicability engine as a match; it can still be
contradicted by other sources, which yields `needs_review`.

## AI claim grounding (0.2.0)

Checking that a cited evidence ID *exists* proved too weak: a local model cited real IDs for
false statements. Each claim must now carry a `quote` of at least 3 words copied from the
evidence it cites. After normalising case, whitespace and typographic quotes/dashes, the quote
must appear in the text of a cited item: its summary, excerpt or stored fields. Any dotted
version, number or ISO date in the statement must also appear there. Claims that fail are
removed, and the reason is recorded per claim. This is a grounding check, not entailment: a model
can quote a true sentence and still draw a wrong conclusion. The check catches invented details
and mis-attributed sources, which were the failures actually observed.

## Reading version wording (auto-resolution, opt-in)

Some CNA records give affected versions as prose ("All versions prior to 26.6.5", "5.3.x prior to
5.3.18+ and all old and unsupported versions"). The version engine cannot compare prose, so the
result is `needs_review`. With `--auto-resolve` (or `CVEPRIO_AUTO_RESOLVE=on`),
`cveprio/llm/versions.py` handles statements about products in the inventory in two stages:

1. **Exact wording patterns (code, no AI).** "prior to / before / earlier than X", "through / up to
   and including X", "X and earlier", "A up to and including B", "5.3.x prior to 5.3.18", in lists
   joined by commas or "and", optionally after the product name and "all versions". The **whole**
   statement must match; any extra words (a platform, a feature, an exception) mean no reading. A
   trailing "and all old/older/unsupported versions" is accepted, but then the reading can only
   confirm *affected*. Such readings are treated like structured ranges and work without any model.
2. **Model reading (only what the patterns cannot read, and only if a model is configured).** The
   model gets the statement, the product name and the record's own status for the statement
   (affected or fixed), never the inventory or installed version. It returns ranges, status,
   conditions and a quote. Code checks that the quote is in the statement, that every version occurs
   in the quote as a whole version, and that the status matches the record's. Two harmless slips are
   repaired, only for *affected* statements and only by widening the range (which can only make "not
   affected" harder): a non-version lower bound such as `default` is dropped, and if both upper-bound
   kinds are given, the one covering more versions is kept. Anything else is rejected.

**Acceptance rules (code):**
- Versions are always compared in code.
- A model reading may confirm *affected* on its own (a wrong "affected" costs an unneeded patch).
- A model reading may contribute to *not affected* only by showing the version is **outside an
  affected range**, never by calling versions "fixed"; only with no conditions, no open-ended wording
  (old, older, earlier, unsupported, any, …) and every version in the statement used; and only when a
  structured source independently says not affected and none says affected.
- A reading of the wording (by pattern or model) never overrides another source's open question,
  such as an NVD platform condition the inventory does not record: the result stays `needs_review`.

Results that relied on a model reading are flagged `resolved_with_ai`, labelled "AI-read wording" in
the dashboard and listed under "What's uncertain"; every reading and rejection is listed in the report.
Model prompt version `2026-10-12.3`. Git commit IDs listed as versions are not sent. Results:
docs/EVALUATION.md, "Auto-resolution". The feature was designed after held-out case h05, which
therefore does not test it independently.

## Distribution advisories (0.2.0)

Distributions backport fixes, so `openssh 1:9.6p1-3ubuntu13.4` can be fixed even though
upstream 9.6p1 is in the affected range. For items with `distro` (`ubuntu:<release>` or
`rhel:<major>`) or a `pkg:deb`/`pkg:rpm` purl with a distro qualifier, the pipeline fetches
the Ubuntu CVE tracker and/or the Red Hat Security Data API, but only for PUBLISHED records.
The installed build is compared with the fixed build using dpkg (`compare_deb`) or rpmvercmp
(`compare_rpm`) rules. A definite distro verdict (fixed, not affected, still needed) wins over
upstream ranges. If the release or package is not listed, or a fetch fails, the result stays
`needs_review`. A 404 from a distro means "no entry", not "not affected". Ubuntu's data
licence is unstated, so fixtures keep only the package-status fields. Red Hat's data is
CC BY 4.0 and credited in every report.

## Held-out evaluation set (0.2.0)

`cveprio holdout-select` samples recent CVEs with a fixed seed: KEV additions in the window,
NVD CVEs with usable CPE ranges, and NVD CVEs with a GitHub advisory, queried as purls through
OSV. Each case gets either the first affected or the first fixed version, and a rotating
business context. Source responses are recorded as fixtures so the evaluation is reproducible
offline. Cases are written **without** expected answers: labels go in `labels.csv`, filled in
by a person from the sources before running the tool, and unlabelled cases are skipped and
counted.

## Retrieval safety

- HTTPS only; hosts restricted to `cveawg.mitre.org`, `services.nvd.nist.gov`,
  `api.first.org`, `www.cisa.gov`, `api.osv.dev` (POST JSON queries only for OSV), `ubuntu.com`,
  `access.redhat.com`. No user-supplied or retrieved URL is ever fetched
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
3. **Citation and quote validation** (every claim must quote its cited evidence verbatim) and
   **rating overrides** against deterministic findings.
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
