"""Report text: known / uncertain lists, and Markdown rendering.

Every bullet carries evidence IDs in brackets; the Evidence table at the end of
each report maps IDs to source URL, retrieval time and dates. AI content is in a
separate, labelled section and never mixed into "What is known".
"""

from __future__ import annotations

import json
from pathlib import Path

from cveprio.models import (
    ApplicabilityResult,
    ApplicabilityStatus,
    CveReport,
    EvidenceBundle,
    LlmAnalysis,
    LlmStatus,
    RecordState,
    RunReport,
    SourceName,
    SourceStatus,
    Truth,
)


def _cite(ids: list[str]) -> str:
    return f" [{', '.join(ids)}]" if ids else ""


def known_and_uncertain(bundle: EvidenceBundle, results: list[ApplicabilityResult], llm: LlmAnalysis,
                        context_supplied: bool) -> tuple[list[str], list[str]]:
    known: list[str] = []
    unc: list[str] = []
    st = bundle.get("CVE.state")
    if st:
        known.append(st.summary + _cite([st.id]))
    if bundle.record_state != RecordState.PUBLISHED:
        rej = bundle.get("CVE.rejected")
        if rej and rej.excerpt:
            known.append(f"Rejection reason (source text): {rej.excerpt}" + _cite([rej.id]))
        return known, unc

    if bundle.primary_cvss:
        p = bundle.primary_cvss
        known.append(f"Most severe CVSS {p.version}: {p.base_score} {p.severity} ({p.vector}) from {p.provider}"
                     + _cite([p.evidence_id]))
    if bundle.cwes:
        known.append("Weakness: " + ", ".join(bundle.cwes) + _cite([i for i in ("CVE.cwe", "NVD.cwe")
                                                                       if bundle.get(i)]))
    for name in ("kev_listed", "exploited_in_wild", "public_exploit_claimed"):
        f = bundle.findings.get(name)
        if not f:
            continue
        line = f"{name.replace('_', ' ').capitalize()}: {f.value.value} — {f.detail}" + _cite(f.evidence_ids)
        (known if f.value in (Truth.TRUE, Truth.FALSE) else unc).append(line)
    if bundle.ssvc:
        ev = bundle.get(bundle.ssvc.evidence_id)
        known.append((ev.summary if ev else "SSVC assessment present") + _cite([bundle.ssvc.evidence_id]))
    if bundle.epss:
        ev = bundle.get(bundle.epss.evidence_id)
        known.append((ev.summary if ev else "EPSS score present") + _cite([bundle.epss.evidence_id]))
    else:
        epss_status = bundle.source_status(SourceName.EPSS)
        unc.append(f"No EPSS score available (EPSS source status: {epss_status}).")

    for r in results:
        line = f"{r.asset_id}: {r.software.product} {r.software.version} → {r.status.value}" + _cite(r.evidence_ids)
        if r.status == ApplicabilityStatus.AFFECTED:
            known.append(line + f" (matched by {r.matched_by})")
        elif r.status == ApplicabilityStatus.NOT_AFFECTED:
            known.append(line)
        elif r.status == ApplicabilityStatus.NEEDS_REVIEW:
            unc.append(line + " — " + "; ".join(r.reasons[:3]))

    for c in bundle.conflicts:
        unc.append(f"Conflict ({c.kind}): {c.description}" + _cite(c.evidence_ids))
    for w in bundle.warnings:
        unc.append(w)
    for s in bundle.sources:
        if s.status in (SourceStatus.FAILED, SourceStatus.RATE_LIMITED, SourceStatus.SKIPPED):
            unc.append(f"Source {s.source.value} {s.status.value}: {s.detail or ''}".strip())
    if not context_supplied:
        unc.append("No inventory or business context supplied: whether this CVE affects your environment, and how "
                   "exposed that system is, is unknown (not assumed).")
    if llm.status == LlmStatus.OK and llm.assessment:
        qs = (llm.assessment.exploit_development_difficulty.open_questions
              + llm.assessment.existing_exploit_usability.open_questions)
        who = "scripted demo example" if llm.scripted else "AI-identified"
        unc.extend(f"Open question ({who}): {q}" for q in qs[:6])
    elif llm.status != LlmStatus.NOT_CONFIGURED:
        unc.append(f"AI assessment unavailable ({llm.status.value}): {llm.detail}")
    if bundle.record_state == RecordState.PUBLISHED and bundle.findings.get("exploited_in_wild") and \
            bundle.findings["exploited_in_wild"].value != Truth.TRUE:
        unc.append("Exploit-development difficulty from public evidence is inherently limited: the absence of "
                   "public research does not mean exploitation is hard.")
    return known, unc


# ------------------------------------------------------------------------- markdown


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")


def render_cve_markdown(r: CveReport) -> str:
    b, d = r.bundle, r.decision
    lines = [f"## {r.cve_id} — {d.headline}", ""]
    if r.mode == "offline_demo":
        lines += ["> **OFFLINE DEMO DATA** — recorded fixtures, not live results. See retrieval times below.", ""]
    if b.title or b.description:
        lines += [f"*Source description (untrusted text, verbatim) [CVE.desc]:* {_md_escape((b.title or '') + ' — ' + (b.description or ''))[:700]}", ""]
    lines += [
        f"**Decision:** `{d.label}`" + (f" · priority {d.priority}" if d.priority else "")
        + (" · provisional" if d.provisional else ""),
        "",
        f"**Factors:** exploitation = `{d.factors['exploitation']}`, severity = `{d.factors['severity']}`, "
        f"exposure = `{d.factors['exposure']}` · **Severity-only baseline:** `{d.baseline_label}`",
        "",
        "### What is known (sourced facts)", *[f"- {k}" for k in r.known], "",
        "### What remains uncertain", *([f"- {u}" for u in r.uncertain] or ["- Nothing flagged."]), "",
        "### Why this priority (rule trace)", *[f"{i}. {t}" for i, t in enumerate(d.trace, 1)], "",
        "### Action supported by the evidence", *[f"- {a}" for a in d.actions], "",
        "### What would change the recommendation", *([f"- {c}" for c in d.counterfactuals] or ["- No single "
                                                                                                  "input change identified."]), "",
    ]
    lines += _render_llm(r.llm)
    if r.applicability:
        lines += ["### Applicability details", "", "| Asset | Software | Status | Reasons |", "|---|---|---|---|"]
        for a in r.applicability:
            lines.append(f"| {a.asset_id} | {_md_escape(a.software.product)} {_md_escape(a.software.version)} | "
                         f"{a.status.value} | {_md_escape('; '.join(a.reasons))[:600]} |")
        lines.append("")
    lines += ["### Evidence", "", "| ID | Source | Summary | Retrieved | Published / updated | URL |",
              "|---|---|---|---|---|---|"]
    for e in b.evidence:
        flag = " ⚠ instruction-like text" if "possible_prompt_injection" in e.flags else ""
        ref = e.fields.get("reference_url")
        url = f"{e.url}" + (f" → ref: {ref}" if ref else "")
        lines.append(f"| {e.id} | {e.source.value}{' (demo)' if e.demo else ''} | {_md_escape(e.summary)}{flag} | "
                     f"{e.retrieved_at.isoformat(timespec='seconds')} | {e.published or '-'} / {e.updated or '-'} | "
                     f"{_md_escape(url)} |")
    lines += ["", "**Source retrieval status:** " + "; ".join(
        f"{s.source.value}={s.status.value}" + (" (cache)" if s.from_cache and not s.demo else "")
        for s in b.sources), ""]
    return "\n".join(lines)


def _render_llm(llm: LlmAnalysis) -> list[str]:
    out = ["### AI-assisted assessment (judgement, not fact)", ""]
    if llm.scripted:
        out += ["> **SCRIPTED EXAMPLE** — hand-written by the project author to demonstrate validation in the "
                "offline demo. It was NOT produced by a language model.", ""]
    if llm.status != LlmStatus.OK or not llm.assessment:
        return [*out, f"Status: `{llm.status.value}` — {llm.detail or ''}", ""]
    a = llm.assessment
    out += [f"Provider `{llm.provider}`, model `{llm.model}`. Claims kept after citation validation: "
            f"{llm.supported_claims}/{llm.total_claims}. Ratings are qualitative; no calibrated probability "
            "is implied.", ""]
    d, u = a.exploit_development_difficulty, a.existing_exploit_usability
    out.append(f"**Exploit-development difficulty:** `{d.rating}`")
    for title, claims in (("Prerequisites", d.prerequisites), ("Complexity", d.complexity_factors),
                          ("Research availability", d.research_availability)):
        out += [f"- *{title}:* {c.statement} ({c.type}){_cite(c.evidence_ids)}" for c in claims]
    out.append(f"\n**Existing-exploit usability:** `{u.rating}`")
    for title, claims in (("Exploit evidence", u.exploit_evidence), ("Reliability limits", u.reliability_limitations),
                          ("Required access", u.required_access)):
        out += [f"- *{title}:* {c.statement} ({c.type}){_cite(c.evidence_ids)}" for c in claims]
    if a.summary:
        who = "Scripted summary" if llm.scripted else "Model summary"
        out += ["", f"*{who} (uncited free text):* {_md_escape(a.summary)}"]
    if a.suspicious_instructions_in_evidence:
        out.append("\n⚠ The model reported instruction-like content in the evidence.")
    if llm.removed_claims or llm.rating_overrides:
        out += ["", "**Validation removed/overrode:**"]
        out += [f"- `{i.path}`: {i.problem}" + (f" — “{_md_escape(i.statement)[:160]}”" if i.statement else "")
                for i in llm.removed_claims + llm.rating_overrides]
    return [*out, ""]


def render_markdown(run: RunReport) -> str:
    org = f" · organisation: {run.organization}" if run.organization else ""
    head = ["# CVE prioritization report", "",
            f"Generated {run.generated_at.isoformat(timespec='seconds')} · mode **{run.mode}** · cveprio "
            f"{run.tool_version}{org}", ""]
    head += [f"> {n}" for n in run.notices] + [""]
    head += ["| CVE | Decision | Baseline (CVSS only) | Exploitation | Severity | Exposure |", "|---|---|---|---|---|---|"]
    for r in run.reports:
        f = r.decision.factors
        head.append(f"| {r.cve_id} | {r.decision.label}{' (provisional)' if r.decision.provisional else ''} | "
                    f"{r.decision.baseline_label} | {f.get('exploitation')} | {f.get('severity')} | {f.get('exposure')} |")
    head.append("")
    return "\n".join(head + [render_cve_markdown(r) for r in run.reports])


def write_outputs(run: RunReport, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"json": out_dir / "report.json", "markdown": out_dir / "report.md"}
    paths["json"].write_text(json.dumps(run.model_dump(mode="json"), indent=2))
    paths["markdown"].write_text(render_markdown(run))
    return paths
