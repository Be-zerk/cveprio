"""Live integration checks against the real APIs. Opt-in: CVEPRIO_LIVE_TESTS=1 pytest -m live

These verify that endpoints, schemas and our parsing still agree. They depend on
external services and current data, so they are excluded from the default run.
"""

from __future__ import annotations

import os

import pytest

from cveprio.config import Settings
from cveprio.models import RecordState, SourceStatus, Truth
from cveprio.pipeline import make_runtime, run

pytestmark = [pytest.mark.live,
              pytest.mark.skipif(os.environ.get("CVEPRIO_LIVE_TESTS") != "1", reason="set CVEPRIO_LIVE_TESTS=1")]


@pytest.fixture(scope="module")
def live_reports(tmp_path_factory):
    settings = Settings.from_env()
    settings.cache_path = tmp_path_factory.mktemp("cache") / "c.sqlite"
    rt = make_runtime(settings, offline=False, provider_name="none")
    return {r.cve_id: r for r in run(["CVE-2021-44228", "CVE-2026-11415", "CVE-2099-99999999"], rt).reports}


def test_live_sources_ok_and_schema_parsed(live_reports):
    r = live_reports["CVE-2021-44228"]
    assert {s.source.value: s.status for s in r.bundle.sources} == {
        "cve_org": SourceStatus.OK, "nvd": SourceStatus.OK, "cisa_kev": SourceStatus.OK, "first_epss": SourceStatus.OK}
    assert r.bundle.record_state == RecordState.PUBLISHED
    assert r.bundle.findings["kev_listed"].value == Truth.TRUE
    assert r.bundle.epss is not None and r.bundle.primary_cvss is not None
    assert not r.bundle.evidence[0].demo and r.mode == "live"


def test_live_rejected_and_missing(live_reports):
    assert live_reports["CVE-2026-11415"].decision.label == "NO_ACTION_REJECTED"
    assert live_reports["CVE-2099-99999999"].decision.label == "INVALID_OR_UNPUBLISHED"


def test_live_discovery_finds_known_log4j_cves(tmp_path):
    from cveprio.models import Asset, Inventory, SoftwareItem
    settings = Settings.from_env()
    settings.cache_path = tmp_path / "c.sqlite"
    rt = make_runtime(settings, offline=False, provider_name="none")
    inv = Inventory(assets=[Asset(id="a", name="a", criticality="high", internet_facing=True, software=[
        SoftwareItem(vendor="Apache", product="log4j-core", version="2.14.1",
                     cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                     purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")])])
    report = run([], rt, inv, discover_cves=True, max_cves=20)
    assert report.discovery and {"CVE-2021-44228", "CVE-2021-45046"} <= set(report.discovery.analyzed)
    assert all(q.status == "ok" for q in report.discovery.queries)
