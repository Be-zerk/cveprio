"""Orchestration: retrieve → normalise → applicability → LLM → rules → report models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cveprio import __version__
from cveprio.applicability import assess
from cveprio.config import DEFAULT_FIXTURES, Settings
from cveprio.llm import analyze
from cveprio.llm.providers import NoProvider, Provider, ProviderError, make_provider
from cveprio.models import (
    ApplicabilityResult,
    Asset,
    CveReport,
    Inventory,
    LlmAnalysis,
    LlmStatus,
    RunReport,
)
from cveprio.net import Fetcher, FixtureFetcher, ResponseCache, SafeFetcher
from cveprio.normalize import build_bundle
from cveprio.prioritize import prioritize
from cveprio.report import known_and_uncertain
from cveprio.sources import fetch_cve_org, fetch_epss, fetch_kev, fetch_nvd, normalize_cve_id

NVD_NOTICE = "This product uses the NVD API but is not endorsed or certified by the NVD."
SOURCE_NOTICES = [
    NVD_NOTICE,
    "CVE records: CVE Program (cve.org). KEV: CISA Known Exploited Vulnerabilities catalogue (CC0). "
    "EPSS: FIRST.org Exploit Prediction Scoring System (https://www.first.org/epss).",
]


@dataclass
class Runtime:
    fetcher: Fetcher
    provider: Provider
    settings: Settings
    offline: bool
    provider_error: str | None = None


def make_runtime(settings: Settings, *, offline: bool, provider_name: str | None = None,
                 fixtures: Path = DEFAULT_FIXTURES) -> Runtime:
    if offline:
        fetcher: Fetcher = FixtureFetcher(fixtures)
    else:
        nvd_gap = 0.7 if settings.nvd_api_key else 6.5  # 50 vs 5 requests per rolling 30 s
        fetcher = SafeFetcher(ResponseCache(settings.cache_path),
                              min_interval_s={"services.nvd.nist.gov": nvd_gap, "cveawg.mitre.org": 0.2,
                                              "api.first.org": 0.2})
    if provider_name == "scripted" and not offline:
        raise ProviderError("not_configured", "the scripted provider exists only for the offline demo")
    provider: Provider
    try:
        provider = make_provider(settings, provider_name, scripted_root=fixtures / "scripted_llm")
        error = None
    except ProviderError as err:
        provider, error = NoProvider(), f"{err.kind}: {err}"
    return Runtime(fetcher, provider, settings, offline, error)


def run(cve_ids: list[str], rt: Runtime, inventory: Inventory | None = None,
        now: datetime | None = None) -> RunReport:
    ids = list(dict.fromkeys(normalize_cve_id(c) for c in cve_ids))  # validates before any network call
    kev = fetch_kev(rt.fetcher)
    epss = fetch_epss(rt.fetcher, ids)
    assets: dict[str, Asset] | None = {a.id: a for a in inventory.assets} if inventory else None
    mode: Literal["live", "offline_demo"] = "offline_demo" if rt.offline else "live"
    reports: list[CveReport] = []
    for cid in ids:
        bundle = build_bundle(cid, fetch_cve_org(rt.fetcher, cid),
                              fetch_nvd(rt.fetcher, cid, rt.settings.nvd_api_key), kev, epss,
                              demo=rt.offline, now=now)
        results: list[ApplicabilityResult] = []
        if assets:
            results = [assess(bundle, a.id, item) for a in assets.values() for item in a.software]
        if rt.provider_error:
            llm = LlmAnalysis(status=LlmStatus.NOT_CONFIGURED, provider="none", detail=rt.provider_error)
        else:
            llm = analyze(bundle, rt.provider)
        decision = prioritize(bundle, llm, results, assets)
        known, uncertain = known_and_uncertain(bundle, results, llm, assets is not None)
        reports.append(CveReport(
            generated_at=datetime.now(UTC), tool_version=__version__, mode=mode, cve_id=cid, bundle=bundle,
            applicability=[r for r in results if r.status.value != "no_product_match"], llm=llm,
            decision=decision, known=known, uncertain=uncertain, context_supplied=assets is not None))

    order = {"P1": 0, "P2": 1, "NEEDS_REVIEW": 2, "P3": 3, "P4": 4}
    reports.sort(key=lambda r: (order.get(r.decision.label, 9), r.cve_id))
    notices = list(SOURCE_NOTICES)
    if rt.offline:
        notices.insert(0, "OFFLINE DEMO MODE: data comes from recorded fixtures (see retrieval times), not live "
                          "sources. Results may be out of date.")
    if inventory and inventory.fictional:
        notices.insert(1 if rt.offline else 0, "Inventory and business context are FICTIONAL example data.")
    return RunReport(generated_at=datetime.now(UTC), tool_version=__version__, mode=mode,
                     organization=inventory.organization if inventory else None,
                     fictional_context=bool(inventory and inventory.fictional), reports=reports, notices=notices)
