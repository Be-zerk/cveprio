"""Stage 6: CVE discovery from the inventory, and disputed-record handling."""

from __future__ import annotations

import json

import httpx
import pytest

from cveprio.discovery import discover, searchable_reason
from cveprio.models import Asset, Inventory, SoftwareItem, Truth
from cveprio.net import SafeFetcher
from cveprio.sources import (
    CPE23_WITH_VERSION,
    NVD_BY_CPE,
    KevCatalog,
    discover_nvd_by_cpe,
    discover_osv_by_purl,
)
from tests.conftest import FakeFetcher, cve5_record, nvd_response, synthetic_bundle

LOG4J_CPE = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


@pytest.mark.parametrize("cpe,ok", [
    (LOG4J_CPE, True),
    ("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", False),   # no specific version
    ("cpe:2.3:a:apache:log4j:-:*:*:*:*:*:*:*", False),
    ("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*", False),  # 12 fields instead of 13
    ("cpe:/a:apache:log4j:2.14.1", False),                # CPE 2.2 not supported for search
])
def test_cpe_must_be_versioned_cpe23(cpe, ok):
    assert bool(CPE23_WITH_VERSION.match(cpe)) is ok


def test_searchable_reason_explains_missing_identifiers():
    assert "no cpe or purl" in searchable_reason(None, None)
    assert "@version" in searchable_reason(None, "pkg:maven/org.example/lib")


def _nvd_page(ids, total):
    return {"totalResults": total, "vulnerabilities": [{"cve": {"id": i}} for i in ids]}


def test_nvd_by_cpe_paginates_and_caps():
    url = lambda start: NVD_BY_CPE.format(cpe=LOG4J_CPE, n=200, start=start)  # noqa: E731
    f = FakeFetcher({url(0): (200, _nvd_page([f"CVE-2021-{i:05d}" for i in range(200)], 450)),
                     url(200): (200, _nvd_page([f"CVE-2022-{i:05d}" for i in range(200)], 450))})
    hit = discover_nvd_by_cpe(f, LOG4J_CPE, max_results=400)
    assert hit.status == "truncated" and len(hit.cve_ids) == 400 and "450" in hit.detail


def test_nvd_by_cpe_failure_is_reported():
    hit = discover_nvd_by_cpe(FakeFetcher({}), LOG4J_CPE)
    assert hit.status == "failed" and hit.cve_ids == []


class OsvFetcher(FakeFetcher):
    def __init__(self, pages):
        super().__init__({})
        self.pages, self.bodies = pages, []

    def post_json(self, url, body, **kw):
        self.bodies.append(body)
        from cveprio.net import FetchResult
        from tests.conftest import NOW
        page = self.pages[len(self.bodies) - 1]
        return FetchResult(url=url, status_code=200, body=json.dumps(page).encode(), retrieved_at=NOW)


def test_osv_extracts_cve_aliases_counts_non_cve_and_paginates():
    f = OsvFetcher([
        {"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"]},
                   {"id": "GHSA-xxxx-only", "aliases": []}], "next_page_token": "t1"},
        {"vulns": [{"id": "CVE-2021-45046"}]},
    ])
    hit = discover_osv_by_purl(f, LOG4J_PURL)
    assert hit.status == "ok"
    assert hit.cve_ids == ["CVE-2021-44228", "CVE-2021-45046"] and hit.non_cve_ids == ["GHSA-xxxx-only"]
    assert f.bodies[1]["page_token"] == "t1" and f.bodies[0] == {"package": {"purl": LOG4J_PURL}}


def _kev(ids):
    from cveprio.models import SourceName, SourceOutcome, SourceStatus
    return KevCatalog(SourceOutcome(source=SourceName.KEV, status=SourceStatus.OK), {i: {} for i in ids}, "x", None)


def test_discover_merges_sources_reports_unsearchable_and_caps_kev_first():
    inv = Inventory(assets=[
        Asset(id="web", name="w", software=[SoftwareItem(vendor="Apache", product="log4j-core", version="2.14.1",
                                                         cpe=LOG4J_CPE, purl=LOG4J_PURL)]),
        Asset(id="box", name="b", software=[SoftwareItem(product="mystery", version="1.0")]),
    ])
    nvd_url = NVD_BY_CPE.format(cpe=LOG4J_CPE, n=200, start=0)

    class F(OsvFetcher):
        pass

    f = F([{"vulns": [{"id": "GHSA-a", "aliases": ["CVE-2021-44228"]}, {"id": "GHSA-b", "aliases": ["CVE-2026-0002"]}]}])
    f.responses[nvd_url] = (200, _nvd_page(["CVE-2021-44228", "CVE-2026-0001", "CVE-2025-0003"], 3))
    summary, found_by = discover(inv, f, nvd_api_key=None, kev=_kev(["CVE-2021-44228"]), max_cves=2)
    assert summary.total_found == 4
    assert summary.analyzed == ["CVE-2021-44228", "CVE-2026-0002"]  # KEV first, then newest
    assert set(summary.dropped) == {"CVE-2026-0001", "CVE-2025-0003"}
    assert any("cap" in c for c in summary.caveats)
    assert len(found_by["CVE-2021-44228"]) == 2  # found by both NVD and OSV
    unsearchable = [q for q in summary.queries if q.status == "not_searchable"]
    assert [q.asset_id for q in unsearchable] == ["box"]


def test_osv_host_is_allowlisted_and_post_validated():
    seen = {}

    def handler(req):
        seen["method"], seen["body"] = req.method, json.loads(req.content)
        return httpx.Response(200, json={"vulns": []})

    f = SafeFetcher(resolver=lambda h: ["93.184.216.34"], transport=httpx.MockTransport(handler), sleep=lambda s: None)
    assert discover_osv_by_purl(f, LOG4J_PURL).status == "ok"
    assert seen == {"method": "POST", "body": {"package": {"purl": LOG4J_PURL}}}


def test_cli_discover_requires_live_inventory(capsys):
    from cveprio.cli import main
    assert main(["analyze", "--discover"]) == 2
    assert main(["analyze", "--inventory", "examples/inventory.json", "--discover", "--offline"]) == 2


# ------------------------------------------------------------------ disputed


def test_disputed_tag_flagged_but_priority_not_lowered():
    from cveprio.prioritize import prioritize
    tagged = nvd_response("CVE-1999-99001")
    tagged["vulnerabilities"][0]["cve"]["cveTags"] = [{"sourceIdentifier": "x", "tags": ["disputed"]}]
    b = synthetic_bundle(nvd=(200, tagged))
    plain = synthetic_bundle()
    assert b.findings["disputed"].value == Truth.TRUE and "NVD.tags" in b.findings["disputed"].evidence_ids
    d, d_plain = prioritize(b, None, [], None), prioritize(plain, None, [], None)
    assert (d.label, d.priority) == (d_plain.label, d_plain.priority)
    assert any("disputed" in t for t in d.trace) and any("dispute" in c for c in d.counterfactuals)


def test_dispute_wording_in_description_detected():
    text = ("Deserialization issue in Example. NOTE: the vendor's position is that untrusted data is not an intended "
            "use case.")
    b = synthetic_bundle(record=cve5_record("CVE-1999-99001", description=text))
    assert b.findings["disputed"].value == Truth.TRUE and "text" in b.findings["disputed"].detail


def test_unsupported_when_assigned_warns():
    rec = cve5_record("CVE-1999-99001")
    rec["containers"]["cna"]["tags"] = ["unsupported-when-assigned"]
    b = synthetic_bundle(record=rec)
    assert any("end-of-life" in w for w in b.warnings)
