"""Source adapters: retrieve raw records and report an honest outcome per source.

Adapters do not interpret security meaning; they return parsed JSON plus a
``SourceOutcome``. Interpretation happens in ``cveprio.normalize``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cveprio.models import SourceName, SourceOutcome, SourceStatus
from cveprio.net import Fetcher, FetchError, FetchResult

CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,19})$")

CVE_ORG_RECORD = "https://cveawg.mitre.org/api/cve/{id}"
CVE_ORG_ID = "https://cveawg.mitre.org/api/cve-id/{id}"
NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss?cve={ids}"

EPSS_BATCH = 100  # keep query strings short; API caps the cve parameter at 2000 chars


class InvalidCveId(ValueError):
    pass


def normalize_cve_id(raw: str) -> str:
    """Validate syntax before any network call. Returns the canonical upper-case ID."""
    candidate = raw.strip().upper()
    m = CVE_ID_RE.match(candidate)
    if not m or int(m.group(1)) < 1999:
        raise InvalidCveId(f"not a valid CVE ID: {raw!r} (expected CVE-YYYY-NNNN...)")
    return candidate


@dataclass
class SourceData:
    outcome: SourceOutcome
    payload: Any = None


def _outcome(source: SourceName, status: SourceStatus, url: str, result: FetchResult | None = None,
             err: FetchError | None = None, demo: bool = False) -> SourceOutcome:
    return SourceOutcome(
        source=source, status=status, url=url,
        retrieved_at=result.retrieved_at if result else datetime.now(UTC),
        from_cache=bool(result and result.from_cache), demo=demo,
        http_status=result.status_code if result else (err.http_status if err else None),
        detail=str(err) if err else None,
    )


def _status_for_error(err: FetchError) -> SourceStatus:
    if err.kind == "rate_limited":
        return SourceStatus.RATE_LIMITED
    if err.kind == "not_in_fixtures":
        return SourceStatus.SKIPPED
    return SourceStatus.FAILED


def _parse_json(result: FetchResult) -> Any:
    try:
        return json.loads(result.body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FetchError("parse", f"malformed JSON from {result.url}: {exc}", url=result.url) from exc


def fetch_cve_org(fetcher: Fetcher, cve_id: str) -> SourceData:
    """CVE Program record. 404 -> check the ID endpoint to tell 'reserved' from 'does not exist'."""
    url = CVE_ORG_RECORD.format(id=cve_id)
    try:
        res = fetcher.get(url, accept_status=(200, 404), max_bytes=2 * 1024 * 1024)
        if res.status_code == 200:
            return SourceData(_outcome(SourceName.CVE_ORG, SourceStatus.OK, url, res, demo=fetcher.demo),
                              {"record": _parse_json(res)})
        id_url = CVE_ORG_ID.format(id=cve_id)
        id_res = fetcher.get(id_url, accept_status=(200, 404), max_bytes=64 * 1024)
        id_info = _parse_json(id_res) if id_res.status_code == 200 else None
        out = _outcome(SourceName.CVE_ORG, SourceStatus.NOT_FOUND, url, res, demo=fetcher.demo)
        out.detail = f"no published record; ID endpoint returned HTTP {id_res.status_code}"
        return SourceData(out, {"record": None, "id_info": id_info, "id_url": id_url,
                                "id_retrieved_at": id_res.retrieved_at})
    except FetchError as err:
        return SourceData(_outcome(SourceName.CVE_ORG, _status_for_error(err), url, err=err, demo=fetcher.demo))


def fetch_nvd(fetcher: Fetcher, cve_id: str, api_key: str | None = None) -> SourceData:
    url = NVD_CVE.format(id=cve_id)
    headers = {"apiKey": api_key} if api_key else None  # header, never in the URL/cache key
    try:
        res = fetcher.get(url, headers=headers, max_bytes=4 * 1024 * 1024)
        data = _parse_json(res)
        vulns = data.get("vulnerabilities") or []
        status = SourceStatus.OK if vulns else SourceStatus.NOT_FOUND
        return SourceData(_outcome(SourceName.NVD, status, url, res, demo=fetcher.demo),
                          vulns[0]["cve"] if vulns else None)
    except FetchError as err:
        return SourceData(_outcome(SourceName.NVD, _status_for_error(err), url, err=err, demo=fetcher.demo))


@dataclass
class KevCatalog:
    outcome: SourceOutcome
    entries: dict[str, dict[str, Any]]
    catalog_version: str | None
    date_released: str | None
    subset_of_full_catalog: bool = False


def fetch_kev(fetcher: Fetcher) -> KevCatalog:
    try:
        res = fetcher.get(KEV_FEED, max_bytes=16 * 1024 * 1024, ttl=timedelta(hours=6))
        data = _parse_json(res)
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise FetchError("parse", "KEV feed missing 'vulnerabilities' list", url=KEV_FEED)
        entries = {v["cveID"]: v for v in data["vulnerabilities"] if isinstance(v, dict) and "cveID" in v}
        return KevCatalog(
            _outcome(SourceName.KEV, SourceStatus.OK, KEV_FEED, res, demo=fetcher.demo), entries,
            data.get("catalogVersion"), data.get("dateReleased"),
            subset_of_full_catalog=bool(data.get("x_cveprio_fixture_subset")),
        )
    except FetchError as err:
        return KevCatalog(_outcome(SourceName.KEV, _status_for_error(err), KEV_FEED, err=err, demo=fetcher.demo),
                          {}, None, None)


@dataclass
class EpssBatch:
    outcomes: dict[str, SourceOutcome]
    scores: dict[str, dict[str, Any]]


def fetch_epss(fetcher: Fetcher, cve_ids: list[str]) -> EpssBatch:
    outcomes: dict[str, SourceOutcome] = {}
    scores: dict[str, dict[str, Any]] = {}
    # Offline fixtures are recorded one CVE per URL so any subset can be replayed.
    size = 1 if fetcher.demo else EPSS_BATCH
    ordered = sorted(set(cve_ids))
    for i in range(0, len(ordered), size):
        batch = ordered[i:i + size]
        url = EPSS_API.format(ids=",".join(batch))
        try:
            res = fetcher.get(url, max_bytes=1024 * 1024)
            data = _parse_json(res)
            if not isinstance(data, dict) or not isinstance(data.get("data"), list):
                raise FetchError("parse", "EPSS response missing 'data' list", url=url)
            rows = {r["cve"]: r for r in data["data"] if isinstance(r, dict) and "cve" in r}
            for cid in batch:
                status = SourceStatus.OK if cid in rows else SourceStatus.NOT_FOUND
                outcomes[cid] = _outcome(SourceName.EPSS, status, url, res, demo=fetcher.demo)
                if cid in rows:
                    scores[cid] = rows[cid]
        except FetchError as err:
            for cid in batch:
                outcomes[cid] = _outcome(SourceName.EPSS, _status_for_error(err), url, err=err, demo=fetcher.demo)
    return EpssBatch(outcomes, scores)
