"""Turn raw source payloads into an ``EvidenceBundle`` with provenance.

Every Evidence item gets a stable, human-readable ID (``CVE.desc``, ``NVD.cvss.2``,
``KEV``...) so model citations and report footnotes are easy to audit.

What this module deliberately does *not* do:
* treat KEV absence as "not exploited" (it records ``exploited_in_wild = unknown``);
* treat an "Exploit"-tagged reference as a working exploit (it is a *claim*);
* pick a single "true" CVSS score silently (all scores are kept; disagreements
  become ``Conflict`` items and the rules use the most severe one).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from cveprio.cvss import source_name
from cveprio.models import (
    AffectedEntry,
    Conflict,
    CpeMatch,
    CvssScore,
    EpssValue,
    Evidence,
    EvidenceBundle,
    Finding,
    RecordState,
    SourceName,
    SourceOutcome,
    SourceStatus,
    SsvcValue,
    Truth,
    VersionSpec,
)
from cveprio.sources import EpssBatch, KevCatalog, SourceData

STALE_SSVC_DAYS = 180
STALE_EPSS_DAYS = 7
CVSS_CONFLICT_DELTA = 1.0
MAX_EXPLOIT_REFS = 15
MAX_REMEDIATION_REFS = 10
MAX_EXCERPT = 2000

INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore (all |any )?(previous|prior|above) (instructions|prompts?)",
        r"disregard (the )?(system|previous|above)",
        r"you are now",
        r"system prompt",
        r"\bassistant\s*:",
        r"(set|mark|rate|classify) (the |this )?(priority|severity|risk) (as|to)",
        r"do not (flag|report|mention)",
        r"respond with|output only|return only",
        r"</?(evidence|system|instructions?)>",
        r"\b(note|message|instructions?) (to|for) (the )?(ai|assistant|model|llm|analyst bot)\b",
    )
]


def injection_flags(text: str | None) -> list[str]:
    """Heuristic detector. A hit is surfaced to the reader; it is not the security boundary.

    The real controls are structural: retrieved text is passed to the model only as
    delimited data, model output is schema-validated, and the model cannot set the
    priority (see docs/ARCHITECTURE.md).
    """
    if not text:
        return []
    return ["possible_prompt_injection"] if any(p.search(text) for p in INJECTION_PATTERNS) else []


def _clip(text: str | None) -> str | None:
    if text is None:
        return None
    text = text.replace("\r", "")
    return text if len(text) <= MAX_EXCERPT else text[:MAX_EXCERPT] + " …[truncated]"


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _severity_band(score: float | None) -> str:
    if score is None:
        return "unscored"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


class _Builder:
    def __init__(self, cve_id: str, demo: bool):
        self.bundle = EvidenceBundle(cve_id=cve_id, record_state=RecordState.UNKNOWN, demo=demo)
        self._counters: dict[str, int] = {}
        self.org_names: dict[str, str] = {}  # CVE Program org UUID -> short name (NVD cites some sources by UUID)

    def add(self, prefix: str, **kwargs: Any) -> Evidence:
        n = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = n
        ev_id = prefix if kwargs.pop("singleton", False) else f"{prefix}.{n}"
        excerpt = kwargs.get("excerpt")
        flags = list(kwargs.pop("flags", [])) + injection_flags(excerpt)
        ev = Evidence(id=ev_id, demo=self.bundle.demo, flags=flags, **kwargs)
        self.bundle.evidence.append(ev)
        return ev

    def finding(self, name: str, value: Truth, detail: str, ids: list[str] | None = None) -> None:
        self.bundle.findings[name] = Finding(name=name, value=value, detail=detail, evidence_ids=ids or [])


# ----------------------------------------------------------------------------- CVSS


def _cvss_from_cve5(metric: dict[str, Any], provider: str, provider_type: str) -> list[dict[str, Any]]:
    out = []
    for key, version in (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0")):
        data = metric.get(key)
        if isinstance(data, dict):
            out.append({"version": version, "data": data, "provider": provider, "provider_type": provider_type})
    return out


def _cvss_from_nvd(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key) or []:
            data = dict(entry.get("cvssData") or {})
            data.setdefault("baseSeverity", entry.get("baseSeverity"))
            out.append({"version": str(data.get("version", key[-2:])), "data": data,
                        "provider": entry.get("source", "unknown"), "provider_type": entry.get("type")})
    return out


VERSION_PREFERENCE = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}


def _add_cvss(b: _Builder, raw: dict[str, Any], source: SourceName, url: str, retrieved: datetime,
              prefix: str) -> None:
    d = raw["data"]
    score = d.get("baseScore")
    ev = b.add(
        prefix, source=source, kind="cvss", url=url, retrieved_at=retrieved,
        summary=f"CVSS {raw['version']} base score {score} ({d.get('baseSeverity') or _severity_band(score)}) "
                f"from {raw['provider']}" + (f" [{raw['provider_type']}]" if raw.get("provider_type") else ""),
        fields={"version": raw["version"], "baseScore": score, "vectorString": d.get("vectorString"),
                "provider": raw["provider"], "provider_id": raw.get("provider_id"), "type": raw.get("provider_type")},
    )
    b.bundle.cvss.append(CvssScore(
        version=raw["version"], base_score=score, severity=(d.get("baseSeverity") or _severity_band(score)).upper(),
        vector=d.get("vectorString"), provider=raw["provider"], provider_type=raw.get("provider_type"),
        provider_id=raw.get("provider_id"),
        attack_vector=d.get("attackVector") or d.get("accessVector"),
        attack_complexity=d.get("attackComplexity") or d.get("accessComplexity"),
        attack_requirements=d.get("attackRequirements"),
        privileges_required=d.get("privilegesRequired") or d.get("authentication"),
        user_interaction=d.get("userInteraction"), evidence_id=ev.id,
    ))


def _choose_primary_cvss(b: _Builder) -> None:
    scored = [c for c in b.bundle.cvss if c.base_score is not None]
    if not scored:
        return
    best_version = max(VERSION_PREFERENCE.get(c.version, 0) for c in scored)
    same = [c for c in scored if VERSION_PREFERENCE.get(c.version, 0) == best_version]
    # Conservative: the most severe score of the newest CVSS version wins; disagreement is reported.
    b.bundle.primary_cvss = max(same, key=lambda c: c.base_score or 0.0)
    scores = {c.base_score or 0.0 for c in same}
    if len(same) > 1 and (max(scores) - min(scores) >= CVSS_CONFLICT_DELTA
                          or len({_severity_band(s) for s in scores}) > 1):
        b.bundle.conflicts.append(Conflict(
            kind="cvss_disagreement",
            description="Sources disagree on CVSS " + same[0].version + " base score: "
            + "; ".join(f"{source_name(c.provider)} {c.base_score}" for c in same)
            + ". Rules use the most severe value; verify against the vendor advisory.",
            evidence_ids=[c.evidence_id for c in same],
        ))


# --------------------------------------------------------------------------- CVE.org


def _ingest_cve_org(b: _Builder, data: SourceData) -> None:
    out = data.outcome
    if out.status != SourceStatus.OK or not data.payload or not data.payload.get("record"):
        if out.status == SourceStatus.NOT_FOUND and data.payload:
            info = data.payload.get("id_info") or {}
            state = str(info.get("state", "")).upper()
            if state == "RESERVED":
                b.bundle.record_state = RecordState.RESERVED
                b.add("CVE.state", singleton=True, source=SourceName.CVE_ORG, kind="record_state",
                      url=data.payload["id_url"], retrieved_at=data.payload["id_retrieved_at"],
                      summary="CVE ID is RESERVED: assigned but no public record has been published.",
                      fields={"state": "RESERVED", "cve_year": info.get("cve_year")})
            else:
                b.bundle.record_state = RecordState.NOT_FOUND
                b.add("CVE.state", singleton=True, source=SourceName.CVE_ORG, kind="record_state",
                      url=out.url or "", retrieved_at=out.retrieved_at or datetime.now(UTC),
                      summary="CVE Services reports no record and no assigned ID (CVE_RECORD_DNE / not found).",
                      fields={"http_status": out.http_status})
        return

    rec = data.payload["record"]
    meta = rec.get("cveMetadata", {})
    url, retrieved = out.url or "", out.retrieved_at or datetime.now(UTC)
    state = str(meta.get("state", "")).upper()
    containers = rec.get("containers", {})
    cna = containers.get("cna", {}) or {}
    for c in [cna, *(containers.get("adp", []) or [])]:
        pm = c.get("providerMetadata") or {}
        if pm.get("orgId") and pm.get("shortName"):
            b.org_names[pm["orgId"]] = pm["shortName"]
    if meta.get("assignerOrgId") and meta.get("assignerShortName"):
        b.org_names[meta["assignerOrgId"]] = meta["assignerShortName"]
    b.bundle.record_state = {"PUBLISHED": RecordState.PUBLISHED, "REJECTED": RecordState.REJECTED}.get(
        state, RecordState.UNKNOWN)
    b.add("CVE.state", singleton=True, source=SourceName.CVE_ORG, kind="record_state", url=url,
          retrieved_at=retrieved, published=meta.get("datePublished"), updated=meta.get("dateUpdated"),
          summary=f"CVE record state {state} (assigner {meta.get('assignerShortName')}, data version "
                  f"{rec.get('dataVersion')}).",
          fields={"state": state, "assigner": meta.get("assignerShortName"),
                  "datePublished": meta.get("datePublished"), "dateUpdated": meta.get("dateUpdated")})

    if b.bundle.record_state == RecordState.REJECTED:
        reasons = " ".join(r.get("value", "") for r in cna.get("rejectedReasons", []) if r.get("lang", "en") == "en")
        b.add("CVE.rejected", singleton=True, source=SourceName.CVE_ORG, kind="rejected_reason", url=url,
              retrieved_at=retrieved, updated=meta.get("dateRejected") or meta.get("dateUpdated"),
              summary="Record is REJECTED by its CNA.", excerpt=_clip(reasons))
        return

    desc = next((d.get("value") for d in cna.get("descriptions", []) if str(d.get("lang", "")).startswith("en")),
                None)
    b.bundle.title = cna.get("title")
    b.bundle.description = desc
    cna_tags = sorted({str(t) for t in cna.get("tags", []) or []})
    if cna_tags:
        b.add("CVE.tags", singleton=True, source=SourceName.CVE_ORG, kind="record_tags", url=url,
              retrieved_at=retrieved, summary="CNA record tags: " + ", ".join(cna_tags), fields={"tags": cna_tags})
    b.add("CVE.desc", singleton=True, source=SourceName.CVE_ORG, kind="description", url=url,
          retrieved_at=retrieved, published=meta.get("datePublished"), updated=meta.get("dateUpdated"),
          summary="CNA description of the vulnerability (verbatim, untrusted text).",
          excerpt=_clip(((cna.get("title") or "") + "\n" + (desc or "")).strip()))

    cna_cwes = sorted({d["cweId"] for pt in cna.get("problemTypes", []) for d in pt.get("descriptions", [])
                       if d.get("cweId")})
    if cna_cwes:
        b.add("CVE.cwe", singleton=True, source=SourceName.CVE_ORG, kind="weakness", url=url, retrieved_at=retrieved,
              summary="CNA weakness classification: " + ", ".join(cna_cwes), fields={"cwes": cna_cwes})
        b.bundle.cwes.extend(c for c in cna_cwes if c not in b.bundle.cwes)

    for m in cna.get("metrics", []) or []:
        for raw in _cvss_from_cve5(m, provider=f"CNA:{meta.get('assignerShortName')}", provider_type="cna"):
            _add_cvss(b, raw, SourceName.CVE_ORG, url, retrieved, "CVE.cvss")

    for a in cna.get("affected", []) or []:
        _add_affected(b, a, f"CNA:{meta.get('assignerShortName')}", url, retrieved)

    for adp in containers.get("adp", []) or []:
        short = (adp.get("providerMetadata") or {}).get("shortName") or "ADP"
        adp_updated = (adp.get("providerMetadata") or {}).get("dateUpdated")
        for m in adp.get("metrics", []) or []:
            for raw in _cvss_from_cve5(m, provider=f"ADP:{short}", provider_type="adp"):
                _add_cvss(b, raw, SourceName.CVE_ORG, url, retrieved, "CVE.cvss")
            other = m.get("other") or {}
            if other.get("type") == "ssvc":
                content = other.get("content") or {}
                opts: dict[str, str] = {}
                for o in content.get("options", []):
                    opts.update({k: str(v) for k, v in o.items()})
                ev = b.add("CVE.ssvc", singleton=True, source=SourceName.CVE_ORG, kind="ssvc", url=url,
                           retrieved_at=retrieved, updated=content.get("timestamp") or adp_updated,
                           summary=f"{short} SSVC decision points: Exploitation={opts.get('Exploitation')}, "
                                   f"Automatable={opts.get('Automatable')}, "
                                   f"Technical Impact={opts.get('Technical Impact')} "
                                   f"(assessed {content.get('timestamp')}).",
                           fields={"provider": short, **opts, "timestamp": content.get("timestamp"),
                                   "role": content.get("role"), "version": content.get("version")})
                b.bundle.ssvc = SsvcValue(
                    exploitation=opts.get("Exploitation"), automatable=opts.get("Automatable"),
                    technical_impact=opts.get("Technical Impact"), timestamp=content.get("timestamp"),
                    evidence_id=ev.id)
        if short == "CISA-ADP":
            for a in adp.get("affected", []) or []:
                _add_affected(b, a, f"ADP:{short}", url, retrieved)

    for ref in (cna.get("references") or [])[:200]:
        tags = [t.lower() for t in ref.get("tags", [])]
        if "exploit" in tags:
            b.add("CVE.ref", source=SourceName.CVE_ORG, kind="exploit_reference_claim", url=url,
                  retrieved_at=retrieved,
                  summary="CNA reference tagged 'exploit' (a claim of public exploit material; not verified "
                          "and not downloaded).",
                  fields={"reference_url": ref.get("url"), "tags": ref.get("tags")})


def _add_affected(b: _Builder, a: dict[str, Any], provider: str, url: str, retrieved: datetime) -> None:
    versions = [
        VersionSpec(version=v.get("version"), status=v.get("status"), version_type=v.get("versionType"),
                    less_than=v.get("lessThan"), less_than_or_equal=v.get("lessThanOrEqual"),
                    changes=v.get("changes") or [])
        for v in (a.get("versions") or []) if isinstance(v, dict)
    ]
    label = a.get("product") or a.get("packageName") or "?"
    ev = b.add("CVE.affected", source=SourceName.CVE_ORG, kind="affected_versions", url=url,
               retrieved_at=retrieved,
               summary=f"{provider} lists affected product '{a.get('vendor') or '-'} / {label}' with "
                       f"{len(versions)} version statement(s); default status {a.get('defaultStatus') or 'unspecified'}.",
               fields={"vendor": a.get("vendor"), "product": a.get("product"), "packageName": a.get("packageName"),
                       "defaultStatus": a.get("defaultStatus"), "cpes": a.get("cpes"),
                       "versions": [v.model_dump(exclude_defaults=True) for v in versions]})
    b.bundle.affected.append(AffectedEntry(
        provider=provider, vendor=a.get("vendor"), product=a.get("product"), package_name=a.get("packageName"),
        cpes=a.get("cpes") or [], default_status=a.get("defaultStatus"), versions=versions, evidence_id=ev.id))


# ------------------------------------------------------------------------------- NVD


def _ingest_nvd(b: _Builder, data: SourceData) -> None:
    out = data.outcome
    if out.status != SourceStatus.OK or not data.payload:
        return
    cve = data.payload
    url, retrieved = out.url or "", out.retrieved_at or datetime.now(UTC)
    nvd_status = cve.get("vulnStatus")
    b.add("NVD.status", singleton=True, source=SourceName.NVD, kind="nvd_status", url=url, retrieved_at=retrieved,
          published=cve.get("published"), updated=cve.get("lastModified"),
          summary=f"NVD analysis status: {nvd_status} (last modified {cve.get('lastModified')}).",
          fields={"vulnStatus": nvd_status, "published": cve.get("published"),
                  "lastModified": cve.get("lastModified"), "cisaExploitAdd": cve.get("cisaExploitAdd")})
    if nvd_status == "Rejected":
        return
    nvd_tags = sorted({str(t) for entry in cve.get("cveTags", []) or [] for t in entry.get("tags", []) or []})
    if nvd_tags:
        b.add("NVD.tags", singleton=True, source=SourceName.NVD, kind="record_tags", url=url, retrieved_at=retrieved,
              summary="NVD CVE tags: " + ", ".join(nvd_tags), fields={"tags": nvd_tags})

    for raw in _cvss_from_nvd(cve.get("metrics") or {}):
        if raw["provider"] in b.org_names:  # NVD names some sources only by UUID; resolve via the CVE record
            raw["provider_id"] = raw["provider"]
            raw["provider"] = f"{b.org_names[raw['provider']]} (copy in NVD)"
        _add_cvss(b, raw, SourceName.NVD, url, retrieved, "NVD.cvss")

    nvd_cwes = sorted({d.get("value", "") for w in cve.get("weaknesses", []) for d in w.get("description", [])
                       if d.get("value", "").startswith("CWE-")})
    if nvd_cwes:
        b.add("NVD.cwe", singleton=True, source=SourceName.NVD, kind="weakness", url=url, retrieved_at=retrieved,
              summary="NVD weakness classification: " + ", ".join(nvd_cwes), fields={"cwes": nvd_cwes})
        b.bundle.cwes.extend(c for c in nvd_cwes if c not in b.bundle.cwes)

    matches: list[dict[str, Any]] = []
    for cfg in cve.get("configurations", []) or []:
        is_and = cfg.get("operator") == "AND"
        nodes = cfg.get("nodes", []) or []
        for node in nodes:
            others = [m2["criteria"] for n2 in nodes if n2 is not node for m2 in n2.get("cpeMatch", [])][:5]
            for m in node.get("cpeMatch", []) or []:
                if m.get("vulnerable"):
                    matches.append({**m, "_and": is_and, "_with": others if is_and else []})
    if matches:
        ev = b.add("NVD.cpe", singleton=True, source=SourceName.NVD, kind="cpe_configurations", url=url,
                   retrieved_at=retrieved, updated=cve.get("lastModified"),
                   summary=f"NVD lists {len(matches)} vulnerable CPE match criteria.",
                   fields={"vulnerable_cpe_match_count": len(matches),
                           "sample": [m["criteria"] for m in matches[:10]]})
        b.bundle.cpe_match_total = len(matches)
        for m in matches:
            parts = m["criteria"].split(":")
            if len(parts) < 6:
                continue
            b.bundle.cpe_matches.append(CpeMatch(
                criteria=m["criteria"], part=parts[2], vendor=parts[3], product=parts[4], version=parts[5],
                version_start_including=m.get("versionStartIncluding"),
                version_start_excluding=m.get("versionStartExcluding"),
                version_end_including=m.get("versionEndIncluding"),
                version_end_excluding=m.get("versionEndExcluding"), in_and_node=m["_and"],
                and_with=m["_with"], evidence_id=ev.id))

    seen: set[str] = set()
    n_exploit = n_fix = 0
    for ref in cve.get("references", []) or []:
        ref_url, tags = ref.get("url", ""), ref.get("tags") or []
        if ref_url in seen:
            continue
        seen.add(ref_url)
        if "Exploit" in tags and n_exploit < MAX_EXPLOIT_REFS:
            n_exploit += 1
            b.add("NVD.ref", source=SourceName.NVD, kind="exploit_reference_claim", url=url, retrieved_at=retrieved,
                  summary="NVD reference tagged 'Exploit' — indicates public exploit or PoC material may exist "
                          "at this URL. Not verified, not downloaded; reliability unknown.",
                  fields={"reference_url": ref_url, "tags": tags, "reference_source": ref.get("source")})
        elif {"Patch", "Vendor Advisory", "Mitigation"} & set(tags) and n_fix < MAX_REMEDIATION_REFS:
            n_fix += 1
            b.add("NVD.ref", source=SourceName.NVD, kind="remediation_reference", url=url, retrieved_at=retrieved,
                  summary=f"NVD reference tagged {', '.join(tags)}.",
                  fields={"reference_url": ref_url, "tags": tags})


# --------------------------------------------------------------------- KEV / EPSS


def _ingest_kev(b: _Builder, kev: KevCatalog) -> None:
    out = kev.outcome
    if out.status != SourceStatus.OK:
        b.finding("kev_listed", Truth.RETRIEVAL_FAILED,
                  f"CISA KEV catalogue could not be retrieved ({out.status}: {out.detail}).")
        return
    entry = kev.entries.get(b.bundle.cve_id)
    if entry:
        ev = b.add("KEV", singleton=True, source=SourceName.KEV, kind="kev_entry", url=out.url or "",
                   retrieved_at=out.retrieved_at or datetime.now(UTC), published=entry.get("dateAdded"),
                   summary=f"Listed in CISA KEV (added {entry.get('dateAdded')}; known ransomware use: "
                           f"{entry.get('knownRansomwareCampaignUse')}; federal due date {entry.get('dueDate')}).",
                   fields={k: entry.get(k) for k in ("vendorProject", "product", "vulnerabilityName", "dateAdded",
                                                      "dueDate", "knownRansomwareCampaignUse", "requiredAction")},
                   excerpt=_clip(entry.get("shortDescription")))
        b.finding("kev_listed", Truth.TRUE, "Listed in the CISA Known Exploited Vulnerabilities catalogue.", [ev.id])
    else:
        ev = b.add("KEV", singleton=True, source=SourceName.KEV, kind="kev_absence", url=out.url or "",
                   retrieved_at=out.retrieved_at or datetime.now(UTC), published=kev.date_released,
                   summary=f"Not listed in CISA KEV catalogue version {kev.catalog_version}. Absence does NOT "
                           f"show the vulnerability is unexploited — only that CISA has not added it.",
                   fields={"catalogVersion": kev.catalog_version, "dateReleased": kev.date_released,
                           "fixture_subset": kev.subset_of_full_catalog})
        b.finding("kev_listed", Truth.FALSE,
                  f"Not in KEV catalogue {kev.catalog_version} (absence is not evidence of no exploitation).",
                  [ev.id])
        if kev.subset_of_full_catalog:
            b.bundle.warnings.append("Offline demo uses a trimmed KEV fixture; absence was verified against the "
                                     "full catalogue at capture time only.")


def _ingest_epss(b: _Builder, epss: EpssBatch, now: datetime) -> None:
    out = epss.outcomes.get(b.bundle.cve_id)
    row = epss.scores.get(b.bundle.cve_id)
    if out is None or out.status != SourceStatus.OK or not row:
        return
    try:
        prob, pct = float(row["epss"]), float(row["percentile"])
    except (KeyError, TypeError, ValueError):
        b.bundle.warnings.append("EPSS row was malformed and was ignored.")
        return
    ev = b.add("EPSS", singleton=True, source=SourceName.EPSS, kind="epss", url=out.url or "",
               retrieved_at=out.retrieved_at or now, published=row.get("date"),
               summary=f"EPSS {prob:.4f} (percentile {pct:.4f}) for {row.get('date')}: estimated probability of "
                       f"exploitation activity being observed in the next 30 days. Not a difficulty or impact score.",
               fields={"epss": prob, "percentile": pct, "date": row.get("date")})
    b.bundle.epss = EpssValue(probability=prob, percentile=pct, score_date=str(row.get("date")), evidence_id=ev.id)
    d = _parse_dt(row.get("date"))
    if d and now - d > timedelta(days=STALE_EPSS_DAYS):
        b.bundle.conflicts.append(Conflict(kind="stale_signal", evidence_ids=[ev.id],
                                           description=f"EPSS score is from {row.get('date')} "
                                                       f"(older than {STALE_EPSS_DAYS} days)."))


# -------------------------------------------------------------------- derived facts


DISPUTE_TEXT = re.compile(r"\*\*\s*DISPUTED\s*\*\*|NOTE:\s*(the\s+)?vendor'?s?\s+position|vendor\s+disputes|"
                          r"(is|has been)\s+disputed", re.IGNORECASE)


def _dispute_findings(b: _Builder) -> None:
    """Disputed / unsupported records: structured tags first, then description wording (heuristic)."""
    tag_ids = [e.id for e in b.bundle.evidence if e.kind == "record_tags" and "disputed" in e.fields.get("tags", [])]
    text = b.bundle.description or ""
    if tag_ids:
        b.finding("disputed", Truth.TRUE, "A source tags this record as DISPUTED (someone, often the vendor, "
                  "contests that it is a vulnerability).", tag_ids)
    elif DISPUTE_TEXT.search(text):
        b.finding("disputed", Truth.TRUE, "The description contains dispute wording (e.g. 'NOTE: the vendor's "
                  "position…'); detected from text, not a structured tag.", ["CVE.desc"])
    if "disputed" in b.bundle.findings:
        b.bundle.warnings.append("This CVE is disputed. Priority is NOT lowered automatically; read the dispute and "
                                 "decide whether your use case is affected.")
    eol = [e.id for e in b.bundle.evidence if e.kind == "record_tags"
           and "unsupported-when-assigned" in e.fields.get("tags", [])]
    if eol:
        b.bundle.warnings.append("Tagged 'unsupported-when-assigned': the affected product was already end-of-life; "
                                 "a fix may never be published — plan replacement.")


def _derive(b: _Builder, cve_org: SourceData, nvd: SourceData, now: datetime) -> None:
    bundle = b.bundle
    ev_by_kind: dict[str, list[str]] = {}
    for e in bundle.evidence:
        ev_by_kind.setdefault(e.kind, []).append(e.id)

    nvd_rejected = bool(nvd.payload and nvd.payload.get("vulnStatus") == "Rejected")
    if bundle.record_state == RecordState.UNKNOWN and nvd_rejected:
        bundle.record_state = RecordState.REJECTED
    if (bundle.record_state == RecordState.REJECTED) != nvd_rejected and nvd.outcome.status == SourceStatus.OK:
        bundle.conflicts.append(Conflict(
            kind="status_mismatch", evidence_ids=[i for i in ("CVE.state", "NVD.status") if bundle.get(i)],
            description=f"CVE record state is {bundle.record_state} but NVD status is "
                        f"{nvd.payload.get('vulnStatus') if nvd.payload else 'n/a'}."))

    if bundle.record_state != RecordState.PUBLISHED:
        failed = bundle.record_state == RecordState.UNKNOWN
        for name in ("exploited_in_wild", "public_exploit_claimed", "cvss_scored"):
            if name not in bundle.findings:
                if failed:
                    b.finding(name, Truth.RETRIEVAL_FAILED, "The CVE record could not be retrieved from any source.")
                else:
                    b.finding(name, Truth.NOT_APPLICABLE, f"Record is {bundle.record_state}; no analysis applies.")
        return

    # Exploited in the wild: positive evidence only. Never "false".
    kev = bundle.findings.get("kev_listed")
    ssvc = bundle.ssvc
    exploited_ids = [i for i in ["KEV"] if kev and kev.value == Truth.TRUE]
    if ssvc and ssvc.exploitation == "active":
        exploited_ids.append(ssvc.evidence_id)
    if exploited_ids:
        how = []
        if "KEV" in exploited_ids:
            how.append("it is listed in CISA's Known Exploited Vulnerabilities catalogue")
        if ssvc and ssvc.exploitation == "active":
            how.append("CISA's SSVC assessment rates exploitation as active")
        b.finding("exploited_in_wild", Truth.TRUE, "Attacks have been seen: " + " and ".join(how) + ".", exploited_ids)
    elif kev and kev.value == Truth.RETRIEVAL_FAILED and not ssvc:
        b.finding("exploited_in_wild", Truth.RETRIEVAL_FAILED,
                  "KEV could not be retrieved and no SSVC assessment is available.")
    else:
        b.finding("exploited_in_wild", Truth.UNKNOWN,
                  "No positive evidence of in-the-wild exploitation in the sources checked. This is not proof "
                  "that exploitation has not occurred.", [i for i in ["KEV", ssvc.evidence_id if ssvc else ""] if i])

    # Public exploit material: claims only.
    claim_ids = ev_by_kind.get("exploit_reference_claim", [])
    if ssvc and ssvc.exploitation in ("poc", "active"):
        claim_ids = [ssvc.evidence_id, *claim_ids]
    nvd_ok = nvd.outcome.status == SourceStatus.OK
    if claim_ids:
        n_refs = len([i for i in claim_ids if ".ref" in i])
        parts = []
        if ssvc and ssvc.exploitation in ("poc", "active"):
            parts.append("CISA's SSVC assessment says proof-of-concept code exists")
        if n_refs:
            parts.append(f"{n_refs} reference{'s are' if n_refs != 1 else ' is'} tagged as exploit material")
        b.finding("public_exploit_claimed", Truth.TRUE,
                  "; ".join(parts).capitalize() + ". Whether that code exists, works or is reliable is NOT "
                  "verified by this tool.", claim_ids)
    elif not nvd_ok and not ssvc:
        b.finding("public_exploit_claimed", Truth.RETRIEVAL_FAILED,
                  "NVD references could not be retrieved and no SSVC assessment is available.")
    else:
        b.finding("public_exploit_claimed", Truth.UNKNOWN,
                  "No exploit-tagged references or SSVC PoC signal found. Exploit databases were not searched.")

    _choose_primary_cvss(b)
    _dispute_findings(b)
    if bundle.primary_cvss:
        p = bundle.primary_cvss
        b.finding("cvss_scored", Truth.TRUE, f"CVSS {p.version} {p.base_score} ({p.severity}) from {p.provider}.",
                  [p.evidence_id])
    elif nvd_ok or cve_org.outcome.status == SourceStatus.OK:
        b.finding("cvss_scored", Truth.FALSE, "No CVSS score published by the sources retrieved (scoring backlog "
                  "or not yet analysed).")
    else:
        b.finding("cvss_scored", Truth.RETRIEVAL_FAILED, "CVSS sources could not be retrieved.")

    # Staleness / disagreement of exploitation signals.
    if ssvc:
        ts = _parse_dt(ssvc.timestamp)
        if ssvc.exploitation == "none" and kev and kev.value == Truth.TRUE:
            bundle.conflicts.append(Conflict(
                kind="exploitation_disagreement", evidence_ids=[ssvc.evidence_id, "KEV"],
                description="CISA SSVC says Exploitation=none but the CVE is in KEV; the SSVC entry is likely "
                            "outdated. KEV is treated as authoritative for known exploitation."))
        if ssvc.exploitation == "none" and claim_ids:
            bundle.conflicts.append(Conflict(
                kind="exploitation_disagreement", evidence_ids=[ssvc.evidence_id, *claim_ids[:3]],
                description="SSVC Exploitation=none, but exploit-tagged references exist. Either the references "
                            "post-date the SSVC assessment or are mis-tagged; review manually."))
        if ts and ssvc.exploitation != "active" and now - ts > timedelta(days=STALE_SSVC_DAYS):
            bundle.conflicts.append(Conflict(
                kind="stale_signal", evidence_ids=[ssvc.evidence_id],
                description=f"SSVC Exploitation={ssvc.exploitation} was assessed {ssvc.timestamp[:10] if ssvc.timestamp else '?'}"
                            f" (> {STALE_SSVC_DAYS} days ago) and may no longer reflect current activity."))

    if bundle.affected == [] and bundle.cpe_matches == []:
        bundle.warnings.append("No structured affected-product data (CNA 'affected' or NVD CPE configurations); "
                               "applicability cannot be determined automatically.")

    flagged = [e.id for e in bundle.evidence if "possible_prompt_injection" in e.flags]
    if flagged:
        bundle.warnings.append("Retrieved text in " + ", ".join(flagged) + " contains instruction-like phrases. "
                               "It is treated strictly as data; review those sources manually.")


def build_bundle(
    cve_id: str,
    cve_org: SourceData,
    nvd: SourceData,
    kev: KevCatalog,
    epss: EpssBatch,
    *,
    demo: bool,
    now: datetime | None = None,
) -> EvidenceBundle:
    now = now or datetime.now(UTC)
    b = _Builder(cve_id, demo)
    outcomes: list[SourceOutcome] = [cve_org.outcome, nvd.outcome, kev.outcome]
    if cve_id in epss.outcomes:
        outcomes.append(epss.outcomes[cve_id])
    b.bundle.sources = outcomes

    _ingest_cve_org(b, cve_org)
    _ingest_nvd(b, nvd)
    if b.bundle.record_state in (RecordState.PUBLISHED, RecordState.UNKNOWN):
        _ingest_kev(b, kev)
        _ingest_epss(b, epss, now)
    if b.bundle.record_state == RecordState.UNKNOWN and nvd.outcome.status == SourceStatus.OK and nvd.payload:
        # CVE.org unavailable but NVD has a non-rejected record: proceed, flagged as degraded.
        if nvd.payload.get("vulnStatus") != "Rejected":
            b.bundle.record_state = RecordState.PUBLISHED
            b.bundle.warnings.append("CVE.org record could not be retrieved; record state inferred from NVD.")
    _derive(b, cve_org, nvd, now)

    failed = [s for s in outcomes if s.status in (SourceStatus.FAILED, SourceStatus.RATE_LIMITED)]
    if failed:
        b.bundle.warnings.append("Partial result: " + ", ".join(f"{s.source} {s.status}" for s in failed)
                                 + ". Conclusions depending on these sources are marked retrieval_failed/unknown.")
    return b.bundle
