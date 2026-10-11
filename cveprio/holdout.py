"""Select a held-out evaluation set by a fixed, reproducible rule (``cveprio holdout-select``).

Why: the original 14 evaluation cases were used while the tool was being built, so they flatter it.
This module picks NEW cases mechanically, so neither the developer nor the AI assistant chooses
"easy" ones:

* Pool KEV  — CVEs CISA added to the KEV catalogue in the window (seeded random sample).
* Pool HIGH — CVEs published in the window with a HIGH CVSS v3 severity, not in KEV, that have
              NVD version ranges (seeded random sample).
* Pool PKG  — open-source package CVEs from the HIGH pool that reference a GitHub advisory (GHSA);
              the software item is the package URL from OSV, i.e. the SBOM path.

The software version for each case is taken mechanically from the CVE's own data: alternately the
first affected version (expected: affected) and the first fixed version (expected: not affected).
Expected answers are left EMPTY: a person labels them from the linked sources before running the
evaluation (see evaluation/holdout/LABELING.md).
"""

from __future__ import annotations

import json
import random
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cveprio.net import FetchError, SafeFetcher
from cveprio.sources import fetch_kev

NVD_WINDOW = ("https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start}T00:00:00.000"
              "&pubEndDate={end}T23:59:59.999&cvssV3Severity=HIGH&noRejected&resultsPerPage=2000&startIndex={i}")
NVD_ONE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
CONTEXTS: list[dict[str, Any]] = [
    {"label": "internet-facing, high importance", "criticality": "high", "internet_facing": True},
    {"label": "internal, medium importance", "criticality": "medium", "internet_facing": False},
    {"label": "internal, low importance, firewall restricts access", "criticality": "low", "internet_facing": False,
     "controls": ["reduces_reachability"]},
    {"label": "no context recorded", "criticality": None, "internet_facing": None},
]


def _ranges(cve: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for cfg in cve.get("configurations") or []:
        if cfg.get("operator") == "AND":
            continue  # platform-conditional; keep the set simple to label
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable"):
                    out.append(m)
    return out


def _item_from_nvd(cve: dict[str, Any], want_affected: bool) -> dict[str, Any] | None:
    for m in _ranges(cve):
        parts = m["criteria"].split(":")
        vendor, product, version = parts[3], parts[4], parts[5]
        if want_affected:
            v = m.get("versionStartIncluding") or (version if version not in ("*", "-") else None)
        else:
            v = m.get("versionEndExcluding")
        if not v:
            continue
        cpe = ":".join([*parts[:5], v, *parts[6:]])
        return {"vendor": vendor, "product": product, "version": v, "cpe": cpe,
                "_how": ("first affected version in NVD's range" if want_affected
                         else "first fixed version (NVD 'versionEndExcluding')")}
    return None


def select(fetcher: SafeFetcher, api_key: str | None, *, seed: int = 2026, start: str = "2026-07-01",
           end: str = "2026-09-30", n_kev: int = 8, n_high: int = 8, n_pkg: int = 4) -> list[dict[str, Any]]:
    rng = random.Random(seed)  # noqa: S311 - reproducible sampling, not security-sensitive
    headers = {"apiKey": api_key} if api_key else None

    kev = fetch_kev(fetcher)
    kev_pool = sorted(c for c, e in kev.entries.items() if start <= str(e.get("dateAdded", "")) <= end)

    high: dict[str, dict[str, Any]] = {}
    i = 0
    while True:
        data = json.loads(fetcher.get(NVD_WINDOW.format(start=start, end=end, i=i), headers=headers,
                                      max_bytes=64 * 1024 * 1024).body)
        for v in data.get("vulnerabilities") or []:
            high[v["cve"]["id"]] = v["cve"]
        i += len(data.get("vulnerabilities") or [])
        if not data.get("vulnerabilities") or i >= int(data.get("totalResults", 0)):
            break
    high_pool = sorted(c for c, v in high.items() if c not in kev.entries and _ranges(v))
    ghsa_re = re.compile(r"(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", re.IGNORECASE)
    ghsa = {c: next((m.group(1) for r in v.get("references") or [] if (m := ghsa_re.search(r.get("url", "")))),
                    None) for c, v in high.items()}
    pkg_pool = sorted(c for c in high_pool if ghsa.get(c))

    picked_kev = rng.sample(kev_pool, min(n_kev, len(kev_pool)))
    pkg_order = rng.sample(pkg_pool, len(pkg_pool))  # deterministic order; take the first n_pkg that OSV knows
    picked_high = rng.sample([c for c in high_pool if c not in pkg_order[: n_pkg * 5]], min(n_high, len(high_pool)))

    cases: list[dict[str, Any]] = []

    def add(cve_id: str, pool: str, software: dict[str, Any] | None, note: str) -> None:
        n = len(cases)
        ctx = dict(CONTEXTS[n % len(CONTEXTS)])
        how = software.pop("_how", "") if software else ""
        cases.append({
            "id": f"h{n + 1:02d}", "cve_id": cve_id, "pool": pool,
            "software": software, "asset": {k: v for k, v in ctx.items() if k != "label"},
            "context_label": ctx["label"],
            "selection_note": note + (f" Version chosen mechanically: {how}." if how else ""),
            "links": {"cve.org": f"https://www.cve.org/CVERecord?id={cve_id}",
                      "nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                      "kev": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}"},
            "expected_applicability": None,   # TO BE FILLED BY THE LABELLER
            "acceptable_decisions": [],        # TO BE FILLED BY THE LABELLER
            "rationale": "",                   # TO BE FILLED BY THE LABELLER
        })

    for k, cid in enumerate(picked_kev):
        cve = high.get(cid)
        if cve is None:
            try:
                vulns = json.loads(fetcher.get(NVD_ONE.format(id=cid), headers=headers).body).get("vulnerabilities")
                cve = vulns[0]["cve"] if vulns else None
            except (FetchError, ValueError, KeyError):
                cve = None
        item = (_item_from_nvd(cve, want_affected=k % 2 == 0) or _item_from_nvd(cve, want_affected=k % 2 != 0)) \
            if cve else None
        add(cid, "KEV", item, "Added to CISA KEV in the window." if item else
            "Added to CISA KEV in the window. NVD has no version ranges, so this is a CVE-only case (no software).")
    for k, cid in enumerate(picked_high):
        item = _item_from_nvd(high[cid], want_affected=k % 2 == 0) or _item_from_nvd(high[cid], k % 2 != 0)
        add(cid, "HIGH", item, "HIGH severity, not in KEV.")
    used = 0
    for cid in pkg_order:
        if used >= n_pkg:
            break
        try:
            osv = json.loads(fetcher.get(OSV_VULN.format(id=quote(str(ghsa[cid]))), accept_status=(200,)).body)
        except (FetchError, ValueError):
            continue  # advisory not in OSV: skip to the next candidate in the fixed order
        aff = (osv.get("affected") or [{}])[0]
        purl = (aff.get("package") or {}).get("purl")
        events = [e for r in aff.get("ranges") or [] for e in r.get("events") or []]
        intro = next((e["introduced"] for e in events if e.get("introduced") not in (None, "0")), None)
        fixed = next((e["fixed"] for e in events if e.get("fixed")), None)
        version = (intro or fixed) if used % 2 == 0 else (fixed or intro)
        if not (purl and version):
            continue
        how = "first affected version in OSV" if version == intro else "first fixed version in OSV"
        add(cid, "PKG (SBOM path)", {"product": (aff.get("package") or {}).get("name"), "version": version,
                                     "purl": f"{purl}@{version}", "_how": how},
            f"Open-source package CVE (GitHub advisory {ghsa[cid]}), matched by package URL through OSV like an "
            "SBOM component.")
        used += 1
    return cases


def write_holdout(cases: list[dict[str, Any]], out_dir: Path, *, seed: int, start: str, end: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "about": "HELD-OUT evaluation set, selected mechanically by `cveprio holdout-select` (see cveprio/holdout.py) "
                 f"with seed {seed} from CVEs dated {start} to {end}. None of these CVEs were used while building "
                 "the tool. Expected answers must be filled in by a human labeller from the linked sources BEFORE "
                 "running `cveprio evaluate --set holdout`; see LABELING.md.",
        "review_status": "unlabelled",
        "selection": {"seed": seed, "window": [start, end], "created": datetime.now(UTC).isoformat()},
        "cases": cases,
    }
    path = out_dir / "cases.json"
    path.write_text(json.dumps(doc, indent=2))
    return path


LABEL_COLUMNS = ["id", "cve_id", "software", "version", "context", "expected_applicability", "acceptable_decisions",
                 "rationale"]


def capture_osv(cases: list[dict[str, Any]], out_dir: Path, fetcher: SafeFetcher) -> None:
    """Store OSV's answer for each package-URL case so the offline evaluation sees what live would."""
    from cveprio.net import post_cache_key
    from cveprio.sources import OSV_QUERY
    manifest_path = out_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for c in cases:
        purl = (c.get("software") or {}).get("purl")
        if not purl:
            continue
        body: dict[str, object] = {"package": {"purl": purl}}
        res = fetcher.post_json(OSV_QUERY, body)
        name = f"responses/osv_{c['id']}.json"
        (out_dir / name).write_bytes(res.body)
        manifest["responses"][post_cache_key(OSV_QUERY, body)] = {
            "file": name, "status": res.status_code, "retrieved_at": res.retrieved_at.isoformat()}
    manifest_path.write_text(json.dumps(manifest, indent=1, sort_keys=True))


def write_labeling(cases: list[dict[str, Any]], out_dir: Path) -> None:
    import csv
    with (out_dir / "labels.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(LABEL_COLUMNS)
        for c in cases:
            sw = c.get("software") or {}
            w.writerow([c["id"], c["cve_id"], sw.get("purl") or sw.get("product") or "(none: CVE only)",
                        sw.get("version", ""), c["context_label"], "", "", ""])
    rows = "\n".join(
        f"| {c['id']} | [{c['cve_id']}]({c['links']['nvd']}) | {c['pool']} | "
        f"{(c.get('software') or {}).get('purl') or (c.get('software') or {}).get('product') or '—'} "
        f"{(c.get('software') or {}).get('version', '')} | {c['context_label']} |"
        for c in cases)
    (out_dir / "LABELING.md").write_text(LABELING_GUIDE.replace("{ROWS}", rows).replace("{N}", str(len(cases))))


LABELING_GUIDE = """# Labelling the held-out set

These {N} cases were picked by a fixed rule (`cveprio holdout-select`, seed in `cases.json`).
**Label them yourself, from the sources, before you run the evaluation or look at the tool's output
for these CVEs.** Otherwise you will be marking the tool's homework with its own answers.

## What to fill in (`labels.csv`; open it in Excel, Numbers or Google Sheets)

| Column | Allowed values | Meaning |
|---|---|---|
| `expected_applicability` | `affected`, `not_affected`, `needs_review`, `no_product_match` | Is THIS software version affected? Use `needs_review` if a careful analyst could not decide from the public sources. For "(none: CVE only)" rows use `no_product_match`. |
| `acceptable_decisions` | one or more of `P1 P2 P3 P4 NEEDS_REVIEW NOT_APPLICABLE NOT_IN_INVENTORY`, separated by spaces | Every outcome you would defend for this system and context. P1 fix now · P2 next patch cycle · P3 schedule · P4 low priority. |
| `rationale` | free text | One or two sentences: which source fact you relied on. |

Tip: decide applicability from NVD's "Known Affected Software Configurations" or the vendor advisory;
decide priority from: is it being attacked (CISA KEV), how severe, and how exposed the system in the
`context` column is. "CVE only" rows have no inventory, so the tool's answer is provisional.

When done, set `review_status` in `cases.json` to `labelled_by_author` and run:

```bash
cveprio evaluate --set holdout
```

## Cases

| ID | CVE | Pool | Software (version) | Context |
|---|---|---|---|---|
{ROWS}
"""
