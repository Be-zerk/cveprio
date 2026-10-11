"""Shared test helpers.

Two kinds of test data:
* real recorded responses in fixtures/demo (via FixtureFetcher);
* SYNTHETIC records built here for edge cases real data does not cover
  (prompt injection, conflicting sources, failures). Synthetic IDs use the
  CVE-1999-99xxx range and are never presented as real.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from cveprio.config import DEFAULT_FIXTURES
from cveprio.models import EvidenceBundle
from cveprio.net import FetchError, FetchResult, FixtureFetcher
from cveprio.normalize import build_bundle
from cveprio.sources import (
    CVE_ORG_ID,
    CVE_ORG_RECORD,
    EPSS_API,
    KEV_FEED,
    NVD_CVE,
    fetch_cve_org,
    fetch_epss,
    fetch_kev,
    fetch_nvd,
)

NOW = datetime(2026, 10, 10, 22, 0, tzinfo=UTC)


@pytest.fixture
def fixtures_fetcher() -> FixtureFetcher:
    return FixtureFetcher(DEFAULT_FIXTURES)


def bundle_from(fetcher: Any, cve_id: str) -> EvidenceBundle:
    return build_bundle(cve_id, fetch_cve_org(fetcher, cve_id), fetch_nvd(fetcher, cve_id), fetch_kev(fetcher),
                        fetch_epss(fetcher, [cve_id]), demo=getattr(fetcher, "demo", False), now=NOW)


@pytest.fixture
def real_bundle(fixtures_fetcher: FixtureFetcher):
    cache: dict[str, EvidenceBundle] = {}

    def get(cve_id: str) -> EvidenceBundle:
        if cve_id not in cache:
            cache[cve_id] = bundle_from(fixtures_fetcher, cve_id)
        return cache[cve_id].model_copy(deep=True)

    return get


class FakeFetcher:
    """Serves synthetic responses: url -> (status, json) or an exception."""

    demo = False

    def __init__(self, responses: dict[str, Any]):
        self.responses = responses
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None, max_bytes: int = 0,
            ttl: timedelta = timedelta(0), accept_status: tuple[int, ...] = (200,)) -> FetchResult:
        self.calls.append(url)
        r = self.responses.get(url)
        if r is None:
            raise FetchError("network", f"unexpected url in test: {url}", url=url)
        if isinstance(r, Exception):
            raise r
        status, body = r
        if status not in accept_status:
            raise FetchError("http", f"HTTP {status}", url=url, http_status=status)
        return FetchResult(url=url, status_code=status, body=json.dumps(body).encode(), retrieved_at=NOW)


def cve5_record(cve_id: str, *, description: str = "A synthetic test vulnerability.", state: str = "PUBLISHED",
                affected: list[dict[str, Any]] | None = None, cvss: float | None = 7.5,
                vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                ssvc: dict[str, str] | None = None, ssvc_ts: str = "2026-09-01T00:00:00Z") -> dict[str, Any]:
    cna: dict[str, Any] = {
        "descriptions": [{"lang": "en", "value": description}],
        "affected": affected if affected is not None else
        [{"vendor": "Example", "product": "widget", "defaultStatus": "unaffected",
          "versions": [{"version": "1.0.0", "lessThan": "1.4.2", "status": "affected", "versionType": "semver"}]}],
        "references": [{"url": "https://example.invalid/advisory"}],
        "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": cvss, "baseSeverity": "HIGH", "vectorString": vector,
                                  "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE",
                                  "userInteraction": "NONE"}}] if cvss is not None else [],
    }
    if state == "REJECTED":
        cna = {"rejectedReasons": [{"lang": "en", "value": "Duplicate of another CVE."}]}
    adp = []
    if ssvc:
        adp.append({"providerMetadata": {"shortName": "CISA-ADP", "dateUpdated": ssvc_ts},
                    "metrics": [{"other": {"type": "ssvc", "content": {
                        "timestamp": ssvc_ts, "options": [{k: v} for k, v in ssvc.items()], "version": "2.0.3"}}}]})
    return {"dataType": "CVE_RECORD", "dataVersion": "5.1",
            "cveMetadata": {"cveId": cve_id, "state": state, "assignerShortName": "synthetic",
                            "datePublished": "2026-09-01T00:00:00Z", "dateUpdated": "2026-09-02T00:00:00Z"},
            "containers": {"cna": cna, "adp": adp}}


def nvd_response(cve_id: str, *, status: str = "Analyzed", refs: list[dict[str, Any]] | None = None,
                 cpe: list[dict[str, Any]] | None = None, nvd_score: float | None = None) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    if nvd_score is not None:
        metrics["cvssMetricV31"] = [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
            "version": "3.1", "baseScore": nvd_score, "baseSeverity": "CRITICAL" if nvd_score >= 9 else "HIGH",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "attackVector": "NETWORK"}}]
    cve = {"id": cve_id, "vulnStatus": status, "published": "2026-09-01T00:00:00", "lastModified": "2026-09-02T00:00:00",
           "metrics": metrics, "references": refs or [],
           "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": cpe}]}] if cpe else []}
    return {"totalResults": 1, "vulnerabilities": [{"cve": cve}]}


def kev_feed(entries: list[str]) -> dict[str, Any]:
    return {"catalogVersion": "2026.10.08", "dateReleased": "2026-10-08T00:00:00Z",
            "vulnerabilities": [{"cveID": c, "dateAdded": "2026-10-01", "knownRansomwareCampaignUse": "Unknown",
                                 "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2026-10-22"}
                                for c in entries]}


def synthetic_fetcher(cve_id: str, *, record: dict[str, Any] | None = None, nvd: Any = None,
                      kev: Any = None, epss: Any = None) -> FakeFetcher:
    responses: dict[str, Any] = {
        CVE_ORG_RECORD.format(id=cve_id): (200, record or cve5_record(cve_id)),
        NVD_CVE.format(id=cve_id): nvd if nvd is not None else (200, nvd_response(cve_id)),
        KEV_FEED: kev if kev is not None else (200, kev_feed([])),
        EPSS_API.format(ids=cve_id): epss if epss is not None else
        (200, {"data": [{"cve": cve_id, "epss": "0.01", "percentile": "0.5", "date": "2026-10-10"}]}),
    }
    return FakeFetcher(responses)


def synthetic_bundle(cve_id: str = "CVE-1999-99001", **kwargs: Any) -> EvidenceBundle:
    return bundle_from(synthetic_fetcher(cve_id, **kwargs), cve_id)


__all__ = ["CVE_ORG_ID", "NOW", "FakeFetcher", "bundle_from", "cve5_record", "kev_feed", "nvd_response",
           "synthetic_bundle", "synthetic_fetcher"]


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _fake_post_json(self, url, body, **kw):
    from cveprio.net import post_cache_key
    return self.get(post_cache_key(url, body))


FakeFetcher.post_json = _fake_post_json  # type: ignore[attr-defined]
