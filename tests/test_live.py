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
