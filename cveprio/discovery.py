"""CVE discovery: start from the inventory, find the CVEs that may affect it.

For each software item:
  * ``cpe`` with a concrete version -> NVD CVE API ``virtualMatchString`` (configurations match);
  * ``purl`` with a version          -> OSV.dev ``/v1/query``;
  * neither                          -> reported as NOT SEARCHABLE (never silently skipped).

Discovery is only a candidate list. Every discovered CVE then goes through the normal
pipeline, where the applicability engine re-checks the deployed version against the
CVE's own data, so a discovery false positive ends up "not affected"/"needs review"
rather than a priority.

Completeness limits (reported in every run): results depend on the CPE/purl being right
(e.g. curl is listed under both ``haxx:curl`` and ``haxx:libcurl``); NVD and OSV cover
different things; OSV advisories without a CVE alias are counted but not analysed;
very large result sets are capped.
"""

from __future__ import annotations

from typing import Any

from cveprio.models import DiscoveryQuery, DiscoverySummary, Inventory
from cveprio.net import Fetcher
from cveprio.sources import (
    CPE23_WITH_VERSION,
    PURL_WITH_VERSION,
    KevCatalog,
    discover_nvd_by_cpe,
    discover_osv_by_purl,
)

CAVEATS = [
    "Discovery finds CVEs only for items that have a versioned CPE or purl; items listed as "
    "'not_searchable' were not checked at all.",
    "Results depend on the identifier being right: one product can appear under several CPE names "
    "(e.g. haxx:curl and haxx:libcurl), and a wrong one silently finds fewer CVEs.",
    "NVD and OSV have different coverage; neither is complete. Vendor and Linux-distribution advisories "
    "are not searched.",
    "Discovered CVEs are candidates: each is re-checked against the deployed version before it can get a priority.",
]


def discover(inventory: Inventory, fetcher: Fetcher, *, nvd_api_key: str | None, kev: KevCatalog,
             max_cves: int = 150) -> tuple[DiscoverySummary, dict[str, list[str]]]:
    queries: list[DiscoveryQuery] = []
    found_by: dict[str, list[str]] = {}

    def note(cve: str, how: str) -> None:
        found_by.setdefault(cve, [])
        if how not in found_by[cve]:
            found_by[cve].append(how)

    for asset in inventory.assets:
        for item in asset.software:
            base: dict[str, Any] = {"asset_id": asset.id, "product": item.product, "version": item.version}
            searched = False
            if item.cpe and CPE23_WITH_VERSION.match(item.cpe):
                searched = True
                hit = discover_nvd_by_cpe(fetcher, item.cpe, nvd_api_key)
                queries.append(DiscoveryQuery(**base, method="nvd_cpe", query=item.cpe, status=hit.status,
                                              cve_ids=hit.cve_ids, detail=hit.detail))
                for c in hit.cve_ids:
                    note(c, f"NVD CPE match {item.cpe.split(':')[3]}:{item.cpe.split(':')[4]} ({asset.id})")
            if item.purl and PURL_WITH_VERSION.match(item.purl):
                searched = True
                hit = discover_osv_by_purl(fetcher, item.purl)
                queries.append(DiscoveryQuery(**base, method="osv_purl", query=item.purl, status=hit.status,
                                              cve_ids=hit.cve_ids, non_cve_ids=hit.non_cve_ids, detail=hit.detail))
                for c in hit.cve_ids:
                    note(c, f"OSV {item.purl.split('@')[0]} ({asset.id})")
            if not searched:
                queries.append(DiscoveryQuery(**base, method="none", status="not_searchable",
                                              detail=searchable_reason(item.cpe, item.purl)))

    # Cap: keep KEV-listed CVEs first (known exploitation), then newest first. Dropped IDs are reported.
    all_ids = sorted(found_by, key=lambda c: (c not in kev.entries, _neg_id(c)))
    kept, dropped = all_ids[:max_cves], all_ids[max_cves:]
    caveats = list(CAVEATS)
    if dropped:
        caveats.insert(0, f"{len(dropped)} discovered CVEs exceeded the --max-cves cap ({max_cves}) and were NOT "
                          "analysed (KEV-listed CVEs were kept first, then the newest).")
    skipped = sum(len(q.non_cve_ids) for q in queries)
    if skipped:
        caveats.append(f"{skipped} OSV advisories have no CVE ID and were not analysed (listed per item).")
    failed = [q for q in queries if q.status in ("failed", "rate_limited")]
    if failed:
        caveats.insert(0, f"{len(failed)} discovery lookups failed; CVEs for those items may be missing.")
    summary = DiscoverySummary(queries=queries, total_found=len(all_ids), analyzed=sorted(kept), dropped=dropped,
                               caveats=caveats)
    return summary, {c: found_by[c] for c in kept}


def searchable_reason(cpe: str | None, purl: str | None) -> str:
    if not cpe and not purl:
        return "no cpe or purl in the inventory entry; add one to enable discovery"
    parts = []
    if cpe and not CPE23_WITH_VERSION.match(cpe):
        parts.append("cpe is not a CPE 2.3 string with a specific version")
    if purl and not PURL_WITH_VERSION.match(purl):
        parts.append("purl has no @version")
    return "; ".join(parts)


def _neg_id(cve: str) -> tuple[int, int]:
    _, year, num = cve.split("-")
    return (-int(year), -int(num))
