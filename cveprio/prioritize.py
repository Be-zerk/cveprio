"""Transparent, deterministic prioritisation rules (documented in docs/PRIORITIZATION.md).

The decision uses three factors, each derived from evidence or supplied context:

  exploitation  confirmed | elevated | low_observed | evidence_incomplete
  severity      critical | high | medium | low | unscored        (most severe CVSS, newest version)
  exposure      high | standard | context_unknown | reduced | not_assessed
                | needs_review | not_affected | not_in_inventory

Step 1 (base):    confirmed → P1; elevated → P2; evidence_incomplete → P2;
                  low_observed → P3 if severity ∈ {critical, high, unscored} else P4.
Step 2 (exposure): high → one step up; reduced → one step down (confirmed never below P2);
                  standard / context_unknown / not_assessed → unchanged (latter two are provisional).
Step 3 (gates):   needs_review → label NEEDS_REVIEW (priority shown "if affected");
                  not_affected / not_in_inventory → no priority.

The LLM can influence exactly one thing: when there is *no* exploitation signal
(low_observed) and the validated AI assessment rates exploit development as
"low" with ≥ 2 cited supporting claims, exploitation becomes "elevated". It can
never lower anything, and the bump is shown in the trace as an AI judgement.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from cveprio.models import (
    ApplicabilityResult,
    ApplicabilityStatus,
    Asset,
    Decision,
    EvidenceBundle,
    LlmAnalysis,
    LlmStatus,
    Priority,
    RecordState,
    SourceName,
    SourceStatus,
    Truth,
)

EPSS_ELEVATED = 0.10  # 10% estimated probability of exploitation activity within 30 days
LADDER: list[Priority] = ["P1", "P2", "P3", "P4"]
PRIORITY_MEANING = {
    "P1": "Act now: emergency change / out-of-band patching",
    "P2": "Next patch cycle, ahead of routine work",
    "P3": "Scheduled remediation in normal maintenance",
    "P4": "Backlog / monitor for changes",
}


@dataclass(frozen=True)
class RuleInputs:
    record_state: RecordState
    exploitation: str
    severity: str
    exposure: str


def _step(p: Priority, delta: int, floor: Priority = "P4") -> Priority:
    idx = max(0, min(LADDER.index(p) + delta, LADDER.index(floor)))
    return LADDER[idx]


def decide(x: RuleInputs) -> tuple[str, Priority | None, bool, list[str]]:
    """Pure rule table: (label, priority, provisional, trace)."""
    trace: list[str] = []
    if x.record_state == RecordState.REJECTED:
        return "NO_ACTION_REJECTED", None, False, ["Record is REJECTED → no remediation priority."]
    if x.record_state in (RecordState.RESERVED, RecordState.NOT_FOUND):
        return "INVALID_OR_UNPUBLISHED", None, False, [f"Record is {x.record_state} → nothing to assess."]
    if x.record_state == RecordState.UNKNOWN:
        return "RETRIEVAL_FAILED", None, True, ["CVE record could not be retrieved from any source."]

    if x.exploitation == "confirmed":
        base: Priority = "P1"
        trace.append("Base P1: exploitation confirmed (KEV and/or SSVC active).")
    elif x.exploitation == "elevated":
        base = "P2"
        trace.append("Base P2: exploitation signal elevated (public exploit claimed, EPSS ≥ "
                     f"{EPSS_ELEVATED:.2f}, or validated AI difficulty=low).")
    elif x.exploitation == "evidence_incomplete":
        base = "P2"
        trace.append("Base P2 (conservative): exploitation sources could not be retrieved.")
    else:
        base = "P3" if x.severity in ("critical", "high", "unscored") else "P4"
        trace.append(f"Base {base}: no exploitation signal; severity {x.severity}.")

    provisional = x.exposure in ("context_unknown", "not_assessed", "needs_review")
    p = base
    if x.exposure == "high":
        p = _step(base, -1)
        trace.append(f"Exposure high (internet-facing or high-criticality asset) → {p}.")
    elif x.exposure == "reduced":
        p = _step(base, +1, floor="P2" if x.exploitation == "confirmed" else "P4")
        trace.append(f"Exposure reduced by a documented compensating control → {p}.")
    elif x.exposure == "standard":
        trace.append("Exposure standard (internal, low/medium criticality) → unchanged.")
    elif x.exposure == "context_unknown":
        trace.append("Asset context missing (internet exposure/criticality not supplied) → unchanged, provisional.")
    elif x.exposure == "not_assessed":
        trace.append("No inventory supplied → priority applies only if the product is deployed (provisional).")

    if x.exposure == "needs_review":
        trace.append(f"Applicability ambiguous → NEEDS_REVIEW; would be {p} if confirmed affected.")
        return "NEEDS_REVIEW", p, True, trace
    if x.exposure == "not_affected":
        trace.append("All matching inventory items are not affected → no priority.")
        return "NOT_APPLICABLE", None, False, trace
    if x.exposure == "not_in_inventory":
        trace.append("No inventory item matches the affected products → no priority.")
        return "NOT_IN_INVENTORY", None, False, trace
    return p, p, provisional, trace


def severity_band(bundle: EvidenceBundle) -> str:
    s = bundle.primary_cvss.base_score if bundle.primary_cvss else None
    if s is None:
        return "unscored"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def baseline_label(bundle: EvidenceBundle) -> str:
    """Severity-only baseline (what a CVSS-sorted list would say)."""
    if bundle.record_state != RecordState.PUBLISHED:
        return "N/A"
    return {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}.get(severity_band(bundle), "UNSCORED")


def exploitation_level(bundle: EvidenceBundle, llm: LlmAnalysis | None) -> tuple[str, list[str]]:
    f = bundle.findings
    exploited, claimed = f.get("exploited_in_wild"), f.get("public_exploit_claimed")
    notes: list[str] = []
    if exploited and exploited.value == Truth.TRUE:
        return "confirmed", notes
    epss_high = bool(bundle.epss and bundle.epss.probability >= EPSS_ELEVATED)
    if (claimed and claimed.value == Truth.TRUE) or epss_high:
        return "elevated", notes
    epss_failed = bundle.source_status(SourceName.EPSS) in (SourceStatus.FAILED, SourceStatus.RATE_LIMITED)
    if (exploited and exploited.value == Truth.RETRIEVAL_FAILED) or (
            claimed and claimed.value == Truth.RETRIEVAL_FAILED) or epss_failed:
        return "evidence_incomplete", notes
    if llm and llm.status == LlmStatus.OK and llm.assessment:
        d = llm.assessment.exploit_development_difficulty
        n = len(d.prerequisites) + len(d.complexity_factors) + len(d.research_availability)
        if d.rating == "low" and n >= 2:
            notes.append("AI judgement (validated, cited) rates exploit development as LOW → exploitation "
                         "raised from low_observed to elevated. This is the only way the model affects priority.")
            return "elevated", notes
    return "low_observed", notes


def _asset_exposure(asset: Asset, cve_id: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    if asset.internet_facing is True or asset.criticality in ("high", "critical"):
        level = "high"
    elif asset.internet_facing is False and asset.criticality in ("low", "medium"):
        level = "standard"
    else:
        missing = [n for n, v in (("internet_facing", asset.internet_facing), ("criticality", asset.criticality))
                   if v is None]
        notes.append(f"{asset.id}: context missing ({', '.join(missing)}); not assumed.")
        level = "context_unknown"
    controls = [c for c in asset.compensating_controls if "*" in c.applies_to or cve_id in c.applies_to]
    if controls:
        notes.extend(f"{asset.id}: compensating control ({c.effect}): {c.description} — operator-supplied, "
                     "not verified by this tool." for c in controls)
        level = "reduced" if level in ("high", "standard") else level
    return level, notes


RANK = {"high": 4, "context_unknown": 3, "standard": 2, "reduced": 1}


def exposure_level(cve_id: str, results: list[ApplicabilityResult], assets: dict[str, Asset] | None
                   ) -> tuple[str, list[str]]:
    if assets is None:
        return "not_assessed", []
    relevant = [r for r in results if r.status != ApplicabilityStatus.NO_PRODUCT_MATCH]
    if not relevant:
        return "not_in_inventory", []
    affected = [r for r in relevant if r.status == ApplicabilityStatus.AFFECTED]
    review = [r for r in relevant if r.status == ApplicabilityStatus.NEEDS_REVIEW]
    notes: list[str] = []
    if affected:
        levels = []
        for r in affected:
            lvl, n = _asset_exposure(assets[r.asset_id], cve_id)
            levels.append(lvl)
            notes.extend(n)
        if review:
            notes.append("Other assets need version review: " + ", ".join(sorted({r.asset_id for r in review})))
        return max(levels, key=lambda v: RANK[v]), notes
    if review:
        return "needs_review", notes
    return "not_affected", notes


def _actions(bundle: EvidenceBundle, label: str, results: list[ApplicabilityResult], single_cve: bool,
             assets: dict[str, Asset] | None) -> list[str]:
    acts: list[str] = []
    if label == "NO_ACTION_REJECTED":
        return ["No remediation: the CVE record is rejected. Remove it from tracking and check whether the "
                "issue was re-assigned under another CVE ID [CVE.rejected]."]
    if label == "INVALID_OR_UNPUBLISHED":
        return ["Verify the CVE ID. A reserved ID has no public details yet; re-check later [CVE.state]."]
    if label == "RETRIEVAL_FAILED":
        return ["Retry when sources are reachable; no recommendation can be made from missing data."]
    if label in ("NOT_APPLICABLE", "NOT_IN_INVENTORY"):
        return ["No action for the listed assets. Keep the inventory accurate; re-assess if versions change."]
    fix_refs = [e.id for e in bundle.evidence if e.kind == "remediation_reference"][:3]
    ref_txt = f" [{', '.join(fix_refs)}]" if fix_refs else ""
    for r in results:
        if r.status == ApplicabilityStatus.AFFECTED:
            fixed = f" to a fixed release (sources indicate fixed at/after {r.fixed_version_hint})" \
                if r.fixed_version_hint else " per the vendor advisory"
            acts.append(f"Upgrade {r.software.product} {r.software.version} on {r.asset_id}{fixed}{ref_txt}.")
        elif r.status == ApplicabilityStatus.NEEDS_REVIEW:
            acts.append(f"Confirm the exact build/version (and any platform condition) of {r.software.product} "
                        f"{r.software.version} on {r.asset_id}, then re-run; see reasons [{', '.join(r.evidence_ids)}].")
    if single_cve:
        acts.append("Determine whether an affected product/version is deployed (supply an inventory to automate "
                    f"this); if so, remediate{ref_txt}.")
    kev = bundle.get("KEV")
    if kev and kev.kind == "kev_entry" and kev.fields.get("requiredAction"):
        acts.append("CISA KEV required action (quoted source text) [KEV]: " + str(kev.fields["requiredAction"])[:400])
    if assets:
        for r in results:
            if r.status == ApplicabilityStatus.AFFECTED:
                for c in assets[r.asset_id].compensating_controls:
                    if "*" in c.applies_to or bundle.cve_id in c.applies_to:
                        acts.append(f"Verify the claimed control on {r.asset_id} is in place until patched: "
                                    f"{c.description}.")
    return acts


def _counterfactuals(x: RuleInputs, current: tuple[str, Priority | None], bundle: EvidenceBundle) -> list[str]:
    out: list[str] = []

    def what_if(desc: str, **changes: str) -> None:
        label, p, _, _ = decide(replace(x, **changes))  # type: ignore[arg-type]
        if (label, p) != current:
            out.append(f"{desc} → {label if label not in LADDER else p}")

    if x.record_state != RecordState.PUBLISHED:
        return out
    if x.exploitation != "confirmed":
        what_if("If exploitation in the wild is reported (e.g. KEV listing)", exploitation="confirmed")
    if x.exploitation == "low_observed":
        what_if(f"If public exploit material appears or EPSS rises to ≥ {EPSS_ELEVATED:.2f}", exploitation="elevated")
    if x.exploitation == "evidence_incomplete":
        what_if("If the failed sources show no exploitation signal", exploitation="low_observed")
    if x.exposure == "not_assessed":
        what_if("If no affected product/version is deployed", exposure="not_in_inventory")
    if x.exposure in ("not_assessed", "context_unknown", "needs_review"):
        what_if("If the affected asset is internet-facing or high-criticality", exposure="high")
        what_if("If the affected asset is internal and low/medium criticality", exposure="standard")
    if x.exposure == "needs_review":
        what_if("If the deployed version is confirmed NOT affected", exposure="not_affected")
    if x.exposure in ("high", "standard"):
        what_if("If a verified compensating control removes reachability", exposure="reduced")
        what_if("Once the fix is applied and verified", exposure="not_affected")
    if x.severity == "unscored":
        what_if("If CVSS is published as medium/low", severity="medium")
    if bundle.conflicts:
        out.append("Resolving the listed source conflicts could change the inputs above.")
    return out


def prioritize(bundle: EvidenceBundle, llm: LlmAnalysis | None, results: list[ApplicabilityResult],
               assets: dict[str, Asset] | None) -> Decision:
    exploitation, ex_notes = exploitation_level(bundle, llm)
    severity = severity_band(bundle)
    exposure, exp_notes = exposure_level(bundle.cve_id, results, assets)
    x = RuleInputs(bundle.record_state, exploitation, severity, exposure)
    label, p, provisional, trace = decide(x)
    factors = {"exploitation": exploitation, "severity": severity, "exposure": exposure}
    if bundle.record_state != RecordState.PUBLISHED:
        factors = dict.fromkeys(factors, "n/a")
        ex_notes, exp_notes = [], []
    trace = ex_notes + trace + exp_notes
    if bundle.record_state == RecordState.PUBLISHED and not bundle.primary_cvss:
        trace.append("No CVSS score: severity treated as 'unscored' (handled conservatively, not as low).")
    headline = {
        "NO_ACTION_REJECTED": "Rejected CVE — no remediation needed",
        "INVALID_OR_UNPUBLISHED": "No published record — cannot assess",
        "RETRIEVAL_FAILED": "Sources unavailable — no recommendation",
        "NOT_APPLICABLE": "Not applicable to the supplied inventory",
        "NOT_IN_INVENTORY": "No matching software in the supplied inventory",
        "NEEDS_REVIEW": f"Needs version review (would be {p} if affected)",
    }.get(label, f"{p}: {PRIORITY_MEANING.get(p or '', '')}" + (" (provisional)" if provisional else ""))
    return Decision(
        label=label, priority=p, provisional=provisional, headline=headline,
        factors=factors, trace=trace, baseline_label=baseline_label(bundle),
        counterfactuals=_counterfactuals(x, (label, p), bundle),
        actions=_actions(bundle, label, results, assets is None, assets),
    )
