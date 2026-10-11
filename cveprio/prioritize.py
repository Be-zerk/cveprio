"""Transparent, deterministic prioritisation rules (documented in docs/PRIORITIZATION.md).

The decision uses three factors, each derived from evidence or supplied context:

  exploitation  confirmed | elevated | claimed_unverified | low_observed | evidence_incomplete
  severity      critical | high | medium | low | unscored        (most severe CVSS, newest version)
  exposure      high | standard | context_unknown | reduced | not_assessed
                | needs_review | not_affected | not_in_inventory

Step 1 (base):    confirmed → P1; elevated → P2; evidence_incomplete → P2; claimed_unverified → P3;
                  low_observed → P3 if severity ∈ {critical, high, unscored} else P4.
Step 2 (exposure): high → one step up, but P1 only if exploitation is confirmed or severity is
                  critical/high; reduced → one step down (confirmed never below P2);
                  standard / context_unknown / not_assessed → unchanged (latter two are provisional).
Step 3 (caps):    severity low (CVSS < 4), no confirmed attacks and attack data available
                  → no higher than P3 (missing data never lowers a priority).
Step 4 (gates):   needs_review → label NEEDS_REVIEW (priority shown "if affected");
                  not_affected / not_in_inventory → no priority.

"elevated" needs a strong signal (CISA SSVC poc, EPSS ≥ 0.10, or the AI path below). An
"Exploit"-tagged reference on its own is only "claimed_unverified": in practice those tags
often point at advisories or bug reports (finding from the SBOM run, 2026-10-10).

The LLM can influence exactly one thing: when there is no strong exploitation signal
(low_observed or claimed_unverified) and the validated AI assessment rates exploit development
as "low" with ≥ 2 cited supporting claims, exploitation becomes "elevated". It can never lower
anything, and the bump is shown in the trace as an AI judgement.
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
OUTCOME_WORDS = {
    "P1": "Fix now (P1)", "P2": "Fix in the next patch cycle (P2)", "P3": "Schedule a fix (P3)",
    "P4": "Low priority (P4)", "NEEDS_REVIEW": "needs a version check", "NOT_APPLICABLE": "no action needed",
    "NOT_IN_INVENTORY": "no action needed", "NO_ACTION_REJECTED": "no action needed",
    "INVALID_OR_UNPUBLISHED": "nothing to assess", "RETRIEVAL_FAILED": "no recommendation",
}
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
        return "NO_ACTION_REJECTED", None, False, ["No priority: this CVE was cancelled — the CVE record is REJECTED, "
                                                   "so there is nothing to fix."]
    if x.record_state in (RecordState.RESERVED, RecordState.NOT_FOUND):
        why = "reserved but not yet published" if x.record_state == RecordState.RESERVED else "not found"
        return "INVALID_OR_UNPUBLISHED", None, False, [f"No priority: there are no public details — the CVE ID is {why}."]
    if x.record_state == RecordState.UNKNOWN:
        return "RETRIEVAL_FAILED", None, True, ["No priority: the CVE record could not be loaded — no source returned it."]

    if x.exploitation == "confirmed":
        base: Priority = "P1"
        trace.append("Starts at P1: attackers are known to be using it — exploitation confirmed by the CISA KEV list and/or CISA SSVC Exploitation=active.")
    elif x.exploitation == "elevated":
        base = "P2"
        trace.append("Starts at P2: attack code exists or attacks are likely — exploitation 'elevated': CISA SSVC "
                     f"says proof-of-concept, EPSS ≥ {EPSS_ELEVATED:.2f}, or validated AI difficulty=low.")
    elif x.exploitation == "claimed_unverified":
        base = "P3"
        trace.append("Starts at P3: attack code may be public, unverified — a reference is tagged 'Exploit', but "
                     "there is no CISA proof-of-concept rating, no high EPSS and no known attacks. Such tags often "
                     "point at advisories or bug reports.")
    elif x.exploitation == "evidence_incomplete":
        base = "P2"
        trace.append("Starts at P2 to be safe: attack data could not be checked — exploitation sources failed, so the rules do not assume it is quiet.")
    else:
        base = "P3" if x.severity in ("critical", "high", "unscored") else "P4"
        trace.append(f"Starts at {base}: no sign of attacks — no exploitation signal found; severity on paper is {x.severity}.")

    provisional = x.exposure in ("context_unknown", "not_assessed", "needs_review")
    p = base
    if x.exposure == "high":
        p = _step(base, -1)
        if p == "P1" and not (x.exploitation == "confirmed" or x.severity in ("critical", "high")):
            p = "P2"
            trace.append("Raised to P2 (not P1): the system is exposed or critical — P1 is reserved for confirmed "
                         "attacks or high/critical severity.")
        elif p != base:
            trace.append(f"Raised to {p}: the system is exposed or critical — an affected asset is internet-facing or "
                         "high-criticality (one step up).")
    elif x.exposure == "reduced":
        p = _step(base, +1, floor="P2" if x.exploitation == "confirmed" else "P4")
        trace.append(f"Lowered to {p}: a protection limits access — an operator-declared compensating control applies (one step down; confirmed exploitation never goes below P2).")
    elif x.exposure == "standard":
        trace.append("Stays the same: the systems are internal and not critical — affected assets are internal "
                     "with low/medium criticality.")
    elif x.exposure == "context_unknown":
        trace.append("Stays the same for now: some system details are missing — internet exposure and/or "
                     "criticality were not supplied, so the result is provisional rather than assumed.")
    elif x.exposure == "not_assessed":
        trace.append("Provisional: only applies if you run this software — No inventory supplied; the priority applies only if the product is deployed.")

    if x.severity == "low" and x.exploitation in ("elevated", "claimed_unverified", "low_observed") \
            and p in ("P1", "P2"):
        p = "P3"
        trace.append("Capped at P3: low severity — CVSS below 4 and no confirmed attacks, so it stays at P3 or lower.")

    if x.exposure == "needs_review":
        trace.append(f"Needs review: your version may or may not be affected — applicability is ambiguous; would be {p} if confirmed affected.")
        return "NEEDS_REVIEW", p, True, trace
    if x.exposure == "not_affected":
        trace.append("No priority: your installed versions are not affected — all matching inventory items are outside the affected versions.")
        return "NOT_APPLICABLE", None, False, trace
    if x.exposure == "not_in_inventory":
        trace.append("No priority: this software is not in your inventory — no inventory item matches the affected products.")
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
    ssvc_poc = bool(bundle.ssvc and bundle.ssvc.exploitation in ("poc", "active"))
    if ssvc_poc or epss_high:
        return "elevated", notes
    epss_failed = bundle.source_status(SourceName.EPSS) in (SourceStatus.FAILED, SourceStatus.RATE_LIMITED)
    if (exploited and exploited.value == Truth.RETRIEVAL_FAILED) or (
            claimed and claimed.value == Truth.RETRIEVAL_FAILED) or epss_failed:
        return "evidence_incomplete", notes
    level = "claimed_unverified" if (claimed and claimed.value == Truth.TRUE) else "low_observed"
    if llm and llm.status == LlmStatus.OK and llm.assessment:
        d = llm.assessment.exploit_development_difficulty
        n = len(d.prerequisites) + len(d.complexity_factors) + len(d.research_availability)
        if d.rating == "low" and n >= 2:
            notes.append("AI judgement raised attack likelihood — validated, cited AI judgement rates exploit "
                         f"development as LOW, so exploitation was raised from {level} to elevated. This is the "
                         "only way the model affects priority.")
            return "elevated", notes
    return level, notes


def _asset_exposure(asset: Asset, cve_id: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    if asset.internet_facing is True or asset.criticality in ("high", "critical"):
        level = "high"
    elif asset.internet_facing is False and asset.criticality in ("low", "medium"):
        level = "standard"
    else:
        missing = [n for n, v in (("internet_facing", asset.internet_facing), ("criticality", asset.criticality))
                   if v is None]
        notes.append(f"{asset.id}: importance or internet exposure not recorded — {', '.join(missing)} not "
                     "supplied; not assumed.")
        level = "context_unknown"
    controls = [c for c in asset.compensating_controls if "*" in c.applies_to or cve_id in c.applies_to]
    if controls:
        notes.extend(f"{asset.id}: has a protection in place (not checked by this tool) — {c.description} ({c.effect}); "
                     "operator-supplied, not verified by this tool." for c in controls)
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
            notes.append("Other assets need a version check — " + ", ".join(sorted({r.asset_id for r in review})))
        return max(levels, key=lambda v: RANK[v]), notes
    if review:
        return "needs_review", notes
    return "not_affected", notes


def _actions(bundle: EvidenceBundle, label: str, results: list[ApplicabilityResult], single_cve: bool,
             assets: dict[str, Asset] | None) -> list[str]:
    acts: list[str] = []
    if label == "NO_ACTION_REJECTED":
        return ["No fix needed: this CVE was rejected — remove it from tracking and check whether the issue was "
                "re-assigned under another CVE ID [CVE.rejected]."]
    if label == "INVALID_OR_UNPUBLISHED":
        return ["Check the CVE ID and look again later — a reserved ID has no public details yet [CVE.state]."]
    if label == "RETRIEVAL_FAILED":
        return ["Try again later — the sources could not be reached, and no recommendation can be made from missing data."]
    if label in ("NOT_APPLICABLE", "NOT_IN_INVENTORY"):
        return ["No action needed for the listed systems — keep the inventory accurate and re-check if versions change."]
    fix_refs = [e.id for e in bundle.evidence if e.kind == "remediation_reference"][:3]
    ref_txt = f" [{', '.join(fix_refs)}]" if fix_refs else ""
    for r in results:
        if r.status == ApplicabilityStatus.AFFECTED:
            fixed = f"sources indicate the fix is in version {r.fixed_version_hint} or later" \
                if r.fixed_version_hint else "follow the vendor advisory for the fixed version"
            acts.append(f"Upgrade {r.software.product} on {r.asset_id} — currently {r.software.version}; {fixed}."
                        f"{ref_txt}")
        elif r.status == ApplicabilityStatus.NEEDS_REVIEW:
            acts.append(f"Check the exact version of {r.software.product} on {r.asset_id} — recorded as "
                        f"{r.software.version}; confirm the build and any platform condition, then re-run. See the "
                        f"applicability table for why it is unclear [{', '.join(r.evidence_ids)}].")
    if single_cve:
        acts.append("Find out whether you run an affected version — supply an inventory to automate this; if you "
                    f"do, remediate.{ref_txt}")
    kev = bundle.get("KEV")
    if kev and kev.kind == "kev_entry" and kev.fields.get("requiredAction"):
        acts.append("Follow CISA's official instructions for this flaw — quoted source text: "
                    + str(kev.fields["requiredAction"])[:400] + " [KEV]")
    if assets:
        for r in results:
            if r.status == ApplicabilityStatus.AFFECTED:
                for c in assets[r.asset_id].compensating_controls:
                    if "*" in c.applies_to or bundle.cve_id in c.applies_to:
                        acts.append(f"Confirm the protection on {r.asset_id} is really in place until patched — "
                                    f"{c.description}.")
    return acts


def _counterfactuals(x: RuleInputs, current: tuple[str, Priority | None], bundle: EvidenceBundle) -> list[str]:
    out: list[str] = []

    def what_if(desc: str, detail: str = "", **changes: str) -> None:
        label, p, _, _ = decide(replace(x, **changes))  # type: ignore[arg-type]
        if (label, p) != current:
            out.append(f"{desc} → {OUTCOME_WORDS.get(label, label)}" + (f" — {detail}" if detail else ""))

    if x.record_state != RecordState.PUBLISHED:
        return out
    if x.exploitation != "confirmed":
        what_if("If attackers are reported using it", "e.g. it is added to CISA's KEV list or CISA SSVC says "
                "exploitation is active", exploitation="confirmed")
    if x.exploitation in ("low_observed", "claimed_unverified"):
        what_if("If attack code is confirmed or attacks become likely", f"CISA rates a proof-of-concept as existing, "
                f"or the EPSS score rises to {EPSS_ELEVATED:.2f} or more", exploitation="elevated")
    if x.exploitation == "evidence_incomplete":
        what_if("If the missing sources show no sign of attacks", "the sources that failed are retried and "
                "contain no exploitation signal", exploitation="low_observed")
    if x.exposure == "not_assessed":
        what_if("If you don't run an affected version", "no affected product/version is deployed",
                exposure="not_in_inventory")
    if x.exposure in ("not_assessed", "context_unknown", "needs_review"):
        hi, std = decide(replace(x, exposure="high")), decide(replace(x, exposure="standard"))
        if (hi[0], hi[1]) == (std[0], std[1]):
            if (hi[0], hi[1]) != current:
                lead = "If your version is affected" if x.exposure == "needs_review" else "Once the system details are known"
                out.append(f"{lead} → {OUTCOME_WORDS.get(hi[0], hi[0])}, however exposed the system is — "
                           "internet-facing/critical and internal/non-critical give the same result")
        else:
            prefix = "If your version is affected and the system is" if x.exposure == "needs_review" else "If the system is"
            what_if(f"{prefix} internet-facing or critical", "an affected asset is internet-facing or has "
                    "high/critical criticality", exposure="high")
            what_if(f"{prefix} internal and not critical", "affected assets are internal with low/medium "
                    "criticality", exposure="standard")
    if x.exposure == "needs_review":
        what_if("If your version turns out not to be affected", "the deployed version is confirmed NOT affected",
                exposure="not_affected")
    if x.exposure in ("high", "standard"):
        what_if("If a firewall rule or other protection blocks access to it", "a verified compensating control "
                "removes reachability", exposure="reduced")
        what_if("Once the fix is installed and confirmed", "the fix is applied and verified", exposure="not_affected")
    if x.severity == "unscored":
        what_if("If its severity score comes out medium or low", "CVSS is published as medium/low",
                severity="medium")
    if bundle.conflicts:
        out.append("If the sources' disagreements are resolved → the decision may change — resolving the listed "
                   "source conflicts could change the inputs above.")
    if "disputed" in bundle.findings:
        out.append("If the dispute turns out to be right for your use → no action needed — review concludes the "
                   "disputed issue does not apply to how you use the software.")
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
    if "disputed" in bundle.findings:
        trace.append("Priority kept despite a dispute — the record is disputed; the priority is not lowered "
                     "automatically, pending human review.")
    if bundle.record_state == RecordState.PUBLISHED and not bundle.primary_cvss:
        trace.append("No severity score yet — severity treated as 'unscored' (handled conservatively, not as low).")
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
