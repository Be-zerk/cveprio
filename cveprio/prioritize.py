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
    # Wording only (never used by the rules): the concrete facts behind each factor.
    exploit_why: str = ""   # e.g. "it is on CISA's list of actively attacked flaws"
    exposure_why: str = ""  # e.g. "web-portal-01 is internet-facing and of high importance"
    asset: str = ""         # the system the exposure statement is about
    review_what: str = ""   # e.g. "web-portal-01's Spring Framework 5.3.17"


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
        trace.append(f"Starts at P1: {x.exploit_why or 'attackers are known to be using it'} — rule: flaws that are "
                     "known to be attacked always start at P1.")
    elif x.exploitation == "elevated":
        base = "P2"
        trace.append(f"Starts at P2: {x.exploit_why or 'there is a strong sign of attack code or attacks'} — rule: a "
                     f"CISA proof-of-concept rating, a predicted chance of attacks of {EPSS_ELEVATED:.0%} or more, or a "
                     "validated AI rating of 'easy to exploit' each start at P2.")
    elif x.exploitation == "claimed_unverified":
        base = "P3"
        trace.append(f"Starts at P3: {x.exploit_why or 'a source tags possible attack code, unverified'} — there is no "
                     "CISA proof-of-concept rating, no high predicted chance of attacks and no known attacks. Such "
                     "tags often point at advisories or bug reports, so on their own they count as a weak signal.")
    elif x.exploitation == "evidence_incomplete":
        base = "P2"
        trace.append("Starts at P2 to be safe: attack data could not be checked — exploitation sources failed, so the rules do not assume it is quiet.")
    else:
        base = "P3" if x.severity in ("critical", "high", "unscored") else "P4"
        trace.append(f"Starts at {base}: no sign of attacks — {x.exploit_why or 'no exploitation signal was found'}; "
                     f"the severity score is {x.severity}, so the rules start at {base}.")

    provisional = x.exposure in ("context_unknown", "not_assessed", "needs_review")
    p = base
    if x.exposure == "high":
        p = _step(base, -1)
        if p == "P1" and not (x.exploitation == "confirmed" or x.severity in ("critical", "high")):
            p = "P2"
            trace.append(f"Raised to P2, not P1: {x.exposure_why or 'an affected system is exposed'} — P1 is kept for "
                         f"flaws that are known to be attacked or rated high/critical; this one is rated {x.severity} "
                         "with no confirmed attacks.")
        elif p != base:
            trace.append(f"Raised to {p}: {x.exposure_why or 'an affected system is exposed'} — rule: internet-facing "
                         "systems, and systems of high or critical importance, move the priority up one step.")
        else:
            trace.append(f"Stays at {p}: {x.exposure_why or 'an affected system is exposed'} — it is already at the "
                         "highest level.")
    elif x.exposure == "reduced":
        p = _step(base, +1, floor="P2" if x.exploitation == "confirmed" else "P4")
        why = x.exposure_why or "a declared protection limits access"
        if x.exploitation == "confirmed":
            trace.append(f"Lowered to {p}: {why} — rule: a protection that blocks the usual way in makes an emergency "
                         "change less urgent, but attackers who get inside the network can still reach it, so a "
                         "known-attacked flaw never goes below P2. The tool does not verify the protection; if it "
                         f"does not hold, treat this as {base}.")
        else:
            trace.append(f"Lowered to {p}: {why} — rule: a declared protection moves the priority down one step. "
                         "The tool does not verify it.")
    elif x.exposure == "standard":
        trace.append(f"Stays the same: {x.exposure_why or 'the affected systems are internal and not critical'} — "
                     "rule: internal systems of low or medium importance do not change the priority.")
    elif x.exposure == "context_unknown":
        trace.append(f"Stays the same for now: {x.exposure_why or 'some system details are missing'} — the result is "
                     "marked provisional instead of guessing the missing details.")
    elif x.exposure == "not_assessed":
        trace.append("Provisional: only applies if you run this software — No inventory supplied; the priority applies only if the product is deployed.")

    if x.severity == "low" and x.exploitation in ("elevated", "claimed_unverified", "low_observed") \
            and p in ("P1", "P2"):
        p = "P3"
        trace.append("Capped at P3: the severity score is low — rule: flaws scored below 4 out of 10 that are not "
                     "known to be attacked stay at P3 or lower.")

    if x.exposure == "needs_review":
        trace.append(f"Needs review: it is unclear whether {x.review_what or 'your installed version'} is affected — "
                     f"it would be {p} if it is.")
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
                         "only way the AI assessment affects the priority rules.")
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
        words = {"internet_facing": "internet exposure", "criticality": "importance"}
        notes.append(f"{asset.id}: {' and '.join(words[m] for m in missing)} not recorded — the inventory does not "
                     "say, so the tool does not assume.")
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
            names = ", ".join(sorted({r.asset_id for r in review}))
            notes.append(f"Also check {names} — whether {'they are' if ',' in names else 'it is'} affected could not "
                         "be confirmed automatically.")
        return max(levels, key=lambda v: RANK[v]), [n for n in notes if n.startswith("Also check")]
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

    if x.record_state in (RecordState.RESERVED, RecordState.NOT_FOUND):
        return ["The record is published with affected products and severity → it can then be assessed like any "
                "other CVE, at any priority"]
    if x.record_state == RecordState.UNKNOWN:
        return ["The sources respond on a later run → a normal assessment, at any priority"]
    if x.record_state != RecordState.PUBLISHED:
        return out
    who = x.asset or "the affected system"
    if x.exploitation != "confirmed":
        what_if("If attackers are reported using it", "for example, if CISA adds it to its list of actively attacked "
                "flaws", exploitation="confirmed")
    if x.exploitation in ("low_observed", "claimed_unverified"):
        what_if("If attack code is confirmed to exist", "a CISA proof-of-concept rating, or a predicted chance of "
                f"attacks of {EPSS_ELEVATED:.0%} or more, would have the same effect", exploitation="elevated")
    if x.exploitation == "evidence_incomplete":
        what_if("If the missing sources show no sign of attacks", "once the sources that failed are retried",
                exploitation="low_observed")
    if x.exposure == "not_assessed":
        what_if("If you don't run an affected version", "check whether this software is installed anywhere",
                exposure="not_in_inventory")
    if x.exposure in ("not_assessed", "context_unknown", "needs_review"):
        hi, std = decide(replace(x, exposure="high")), decide(replace(x, exposure="standard"))
        if (hi[0], hi[1]) == (std[0], std[1]):
            if (hi[0], hi[1]) != current:
                lead = (f"If {x.review_what or 'your version'} turns out to be affected" if x.exposure == "needs_review"
                        else f"Once {who}'s details are recorded")
                out.append(f"{lead} → {OUTCOME_WORDS.get(hi[0], hi[0])} — how exposed or important the system is "
                           "would not change this")
        else:
            subject = (who if x.exposure != "not_assessed" else "the system running it")
            pre = f"If {x.review_what} is affected and {subject}" if x.exposure == "needs_review" else f"If {subject}"
            what_if(f"{pre} is internet-facing", "recording it as high or critical importance would have the same "
                    "effect", exposure="high")
            what_if(f"{pre} is internal and of low importance", "medium importance gives the same result",
                    exposure="standard")
    if x.exposure == "needs_review":
        what_if(f"If {x.review_what or 'your version'} turns out not to be affected", "check the exact build and any "
                "platform condition", exposure="not_affected")
    if x.exposure in ("high", "standard"):
        what_if(f"If a protection such as a firewall rule blocks access to {who}", "a declared protection lowers the "
                "priority by one step", exposure="reduced")
        what_if(f"Once {who} is upgraded and checked", "the fix is installed and confirmed", exposure="not_affected")
    if x.severity == "unscored":
        what_if("If its severity score is published as medium", "a low score gives the same result",
                severity="medium")
    if bundle.conflicts:
        out.append("If the sources' disagreements are resolved → the decision may change — see 'What's uncertain' "
                   "for which sources disagree.")
    if "disputed" in bundle.findings:
        out.append("If the dispute turns out to be right for your use → no action needed — review concludes the "
                   "disputed issue does not apply to how you use the software.")
    return out


def _pct(p: float) -> str:
    return ">99.9%" if p >= 0.9995 else "<0.1%" if p < 0.0005 else f"{p * 100:.1f}%"


def _describe_asset(a: Asset) -> str:
    bits = []
    if a.internet_facing is True:
        bits.append("internet-facing")
    elif a.internet_facing is False:
        bits.append("internal")
    if a.criticality:
        bits.append(f"of {a.criticality} importance")
    return " and ".join(bits)


def _wording(bundle: EvidenceBundle, exploitation: str, exposure: str, results: list[ApplicabilityResult],
             assets: dict[str, Asset] | None) -> dict[str, str]:
    """Concrete facts for the trace and counterfactual sentences. Wording only; never changes a decision."""
    w = {"exploit_why": "", "exposure_why": "", "asset": "", "review_what": ""}
    kev, ssvc, epss = bundle.get("KEV"), bundle.ssvc, bundle.epss
    claimed = bundle.findings.get("public_exploit_claimed")
    n_refs = len([i for i in (claimed.evidence_ids if claimed else []) if ".ref" in i])
    if exploitation == "confirmed":
        parts = []
        if kev and kev.kind == "kev_entry":
            parts.append(f"it has been on CISA's list of actively attacked flaws since {kev.fields.get('dateAdded')}")
        if ssvc and ssvc.exploitation == "active":
            parts.append("CISA rates exploitation as active")
        w["exploit_why"] = " and ".join(parts)
    elif exploitation == "elevated":
        if ssvc and ssvc.exploitation == "poc":
            w["exploit_why"] = "CISA says demo attack code exists"
        elif epss and epss.probability >= EPSS_ELEVATED:
            w["exploit_why"] = f"the predicted chance of attacks in the next 30 days is {_pct(epss.probability)}"
        else:
            w["exploit_why"] = "the validated AI assessment rates it easy to exploit"
    elif exploitation == "claimed_unverified":
        noun = "source" if n_refs == 1 else "sources"
        w["exploit_why"] = f"{n_refs} unverified {noun} tag possible attack code" if n_refs != 1 else \
            "1 unverified source tags possible attack code"
        if epss:
            w["exploit_why"] += f" ({_pct(epss.probability)} predicted chance of attacks)"
    elif exploitation == "low_observed":
        w["exploit_why"] = "not on CISA's attacked list and no public attack code found" + (
            f"; {_pct(epss.probability)} predicted chance of attacks" if epss else "")

    affected = [r for r in results if r.status == ApplicabilityStatus.AFFECTED]
    review = [r for r in results if r.status == ApplicabilityStatus.NEEDS_REVIEW]
    if review:
        r = review[0]
        w["review_what"] = f"{r.asset_id}'s {r.software.product} {r.software.version}"
        w["asset"] = r.asset_id
    if assets and affected:
        def pick(pred: object) -> ApplicabilityResult:
            return next((r for r in affected if pred(assets[r.asset_id])), affected[0])  # type: ignore[operator]
        if exposure == "high":
            r = pick(lambda a: a.internet_facing is True or a.criticality in ("high", "critical"))
        elif exposure == "context_unknown":
            r = pick(lambda a: a.internet_facing is None or a.criticality is None)
        elif exposure == "reduced":
            r = pick(lambda a: bool(a.compensating_controls))
        else:
            r = affected[0]
        a = assets[r.asset_id]
        w["asset"] = a.id
        if exposure in ("high", "standard"):
            others = len({x.asset_id for x in affected}) - 1
            w["exposure_why"] = f"{a.id} is {_describe_asset(a)}" + (
                f" (+{others} other affected system{'s' if others > 1 else ''})" if others > 0 else "")
        elif exposure == "context_unknown":
            missing = [n for n, v in (("internet exposure", a.internet_facing), ("importance", a.criticality))
                       if v is None]
            w["exposure_why"] = f"{a.id}'s {' and '.join(missing)} {'is' if len(missing) == 1 else 'are'} not recorded"
        elif exposure == "reduced":
            ctrl = next((c.description for c in a.compensating_controls), "a declared protection")
            w["exposure_why"] = f"{a.id} has a declared protection ({ctrl[:90]})"
    return w


def prioritize(bundle: EvidenceBundle, llm: LlmAnalysis | None, results: list[ApplicabilityResult],
               assets: dict[str, Asset] | None) -> Decision:
    exploitation, ex_notes = exploitation_level(bundle, llm)
    severity = severity_band(bundle)
    exposure, exp_notes = exposure_level(bundle.cve_id, results, assets)
    x = RuleInputs(bundle.record_state, exploitation, severity, exposure,
                   **_wording(bundle, exploitation, exposure, results, assets))
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
