"""Report text: known / uncertain lists, and Markdown rendering.

Every bullet carries evidence IDs in brackets; the Evidence table at the end of
each report maps IDs to source URL, retrieval time and dates. AI content is in a
separate, labelled section and never mixed into "What is known".
"""

from __future__ import annotations

import json
from pathlib import Path

from cveprio.cvss import cwe_name, cwe_short, source_name
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

FINDING_LABEL = {
    "kev_listed": "On the US government's list of actively attacked flaws (KEV)",
    "exploited_in_wild": "Known to be exploited by attackers",
    "public_exploit_claimed": "Attack code reported to be public",
    "disputed": "Disputed by the vendor or others",
}
VALUE_WORD = {"true": "Yes", "false": "No", "unknown": "Unknown", "not_applicable": "Not applicable",
              "retrieval_failed": "Could not check"}

# Every bullet is "SHORT — DETAILS [evidence IDs]". The dashboard shows SHORT and tucks DETAILS and the
# evidence IDs behind a per-bullet toggle; Markdown/JSON keep the whole string. SHORT never contains SEP.
SEP = " — "

CONFLICT_SHORT = {
    "cvss_disagreement": "Sources give different severity scores",
    "stale_signal": "Some evidence may be out of date",
    "exploitation_disagreement": "Sources disagree about exploitation",
    "status_mismatch": "Sources disagree about the record's status",
}
WARNING_SHORT = [
    ("trimmed KEV", "Demo data: the attacked-flaws list (KEV) is a reduced copy"),
    ("Partial result", "Some data sources failed"),
    ("disputed", "This CVE is disputed"),
    ("instruction-like", "Source text contains instruction-like wording"),
    ("No structured affected-product", "No machine-readable list of affected versions"),
    ("unsupported-when-assigned", "Product was already end-of-life"),
    ("inferred from NVD", "CVE.org record unavailable"),
]


def _cite(ids: list[str]) -> str:
    return f" [{', '.join(ids)}]" if ids else ""


def item(short: str, detail: str = "", ids: list[str] | None = None) -> str:
    short = short.replace(SEP, ", ").strip()
    return short + (SEP + detail.strip() if detail.strip() else "") + _cite(ids or [])


def _shorten(text: str, limit: int = 70) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(",;:") + "…"


def _date(value: str | None) -> str:
    return (value or "")[:10] or "unknown date"


def known_and_uncertain(bundle: EvidenceBundle, results: list[ApplicabilityResult], llm: LlmAnalysis,
                        context_supplied: bool) -> tuple[list[str], list[str]]:
    known: list[str] = []
    unc: list[str] = []
    st = bundle.get("CVE.state")
    if st:
        state = {"PUBLISHED": "Published (active)", "REJECTED": "Cancelled (rejected)",
                 "RESERVED": "Reserved, no details published yet"}.get(
            str(st.fields.get("state", "")).upper(), "Not found")
        bits = [f"assigned by {st.fields['assigner']}" if st.fields.get("assigner") else "",
                f"published {_date(st.published)}" if st.published else "",
                f"last updated {_date(st.updated)}" if st.updated else ""]
        known.append(item(f"CVE status: {state}", "; ".join(b for b in bits if b) or st.summary, [st.id]))
    if bundle.record_state != RecordState.PUBLISHED:
        rej = bundle.get("CVE.rejected")
        if rej and rej.excerpt:
            known.append(item("Reason given for rejection", f"(source text) {rej.excerpt}", [rej.id]))
        return known, unc

    if bundle.primary_cvss:
        p = bundle.primary_cvss
        same_version = [c for c in bundle.cvss if c.base_score is not None and c.version == p.version]
        n, distinct = len({c.provider for c in same_version}), {c.base_score for c in same_version}
        note = ("" if n < 2 else f"; {n} sources agree" if len(distinct) == 1
                else f"; the highest of {len(distinct)} different scores from {n} sources (see What's uncertain)")
        known.append(item(f"Severity: {p.base_score} / 10 ({(p.severity or '').capitalize()})",
                          f"CVSS {p.version} score from {source_name(p.provider)}{note}. Full breakdown in "
                          "Severity score details.", [p.evidence_id]))
    if bundle.cwes:
        first, more = cwe_short(bundle.cwes[0]), len(bundle.cwes) - 1
        known.append(item(f"Type of flaw: {first}" + (f" (+{more} more)" if more else ""),
                          "; ".join(f"{c}: {cwe_name(c) or 'name not in the MITRE list'}" for c in bundle.cwes)
                          + ". CWE = MITRE's Common Weakness Enumeration.",
                          [i for i in ("CVE.cwe", "NVD.cwe") if bundle.get(i)]))
    for name in ("kev_listed", "exploited_in_wild", "public_exploit_claimed", "disputed"):
        f = bundle.findings.get(name)
        if not f:
            continue
        line = item(f"{FINDING_LABEL[name]}: {VALUE_WORD[f.value.value]}", f.detail, f.evidence_ids)
        (known if f.value in (Truth.TRUE, Truth.FALSE) else unc).append(line)
    if bundle.ssvc:
        s = bundle.ssvc
        plain = {"active": "attacks have been seen", "poc": "demo attack code exists",
                 "none": "no attacks or attack code known"}
        known.append(item(f"CISA's rating: {plain.get(s.exploitation or '', s.exploitation or 'n/a')}",
                          f"CISA SSVC decision points: Exploitation={s.exploitation}, Automatable={s.automatable}, "
                          f"Technical Impact={s.technical_impact}; assessed {_date(s.timestamp)}.", [s.evidence_id]))
    if bundle.epss:
        e = bundle.epss
        pct = ">99.9%" if e.probability >= 0.9995 else "<0.1%" if e.probability < 0.0005 else f"{e.probability * 100:.1f}%"
        known.append(item(f"Predicted chance of attacks in the next 30 days: {pct}",
                          f"EPSS {e.probability:.4f}, higher than {e.percentile * 100:.1f}% of all scored CVEs, scored "
                          f"{e.score_date} (FIRST EPSS model). Estimates exploitation activity, not difficulty or impact.", [e.evidence_id]))
    else:
        unc.append(item("No EPSS score available", f"EPSS source status: {bundle.source_status(SourceName.EPSS)}."))

    for r in results:
        who = f"{r.asset_id}: {r.software.product} {r.software.version}"
        detail = "; ".join(x.replace("[affected] ", "").replace("[not_affected] ", "").replace("[ambiguous] ", "")
                           for x in r.reasons)
        if r.status == ApplicabilityStatus.AFFECTED:
            known.append(item(f"{who} is affected", f"Matched by {r.matched_by}. {detail}", r.evidence_ids))
        elif r.status == ApplicabilityStatus.NOT_AFFECTED:
            known.append(item(f"{who} is not affected", detail, r.evidence_ids))
        elif r.status == ApplicabilityStatus.NEEDS_REVIEW:
            unc.append(item(f"{who} needs a manual version check", detail, r.evidence_ids))

    for c in bundle.conflicts:
        unc.append(item(CONFLICT_SHORT.get(c.kind, "Sources conflict"), c.description, c.evidence_ids))
    for w in bundle.warnings:
        short = next((label for key, label in WARNING_SHORT if key in w), w.split(". ")[0][:80])
        unc.append(item(short, w))
    for src in bundle.sources:
        if src.status in (SourceStatus.FAILED, SourceStatus.RATE_LIMITED, SourceStatus.SKIPPED):
            unc.append(item(f"Source {src.source.value}: {src.status.value.replace('_', ' ')}", src.detail or ""))
    if not context_supplied:
        unc.append(item("We don't know if you run this software", "No inventory or business context was supplied, so whether "
                        "this CVE affects you, and how exposed that system is, is unknown (not assumed)."))
    if llm.status == LlmStatus.OK and llm.assessment:
        qs = (llm.assessment.exploit_development_difficulty.open_questions
              + llm.assessment.existing_exploit_usability.open_questions)
        who = "scripted demo example" if llm.scripted else "raised by the AI assessment"
        unc.extend(item(f"Open question: {_shorten(q)}", f"{q} (Source: {who}; not verified.)") for q in qs[:6])
    elif llm.status != LlmStatus.NOT_CONFIGURED:
        unc.append(item("AI assessment unavailable", f"{llm.status.value}: {llm.detail}"))
    if bundle.record_state == RecordState.PUBLISHED and bundle.findings.get("exploited_in_wild") and \
            bundle.findings["exploited_in_wild"].value != Truth.TRUE:
        unc.append(item("Little public research doesn't mean it's hard to exploit", "Exploit-development difficulty judged from "
                        "public evidence is inherently limited: the absence of public research does not mean "
                        "exploitation is hard."))
    return known, unc


# ------------------------------------------------------------------------- markdown


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")


def render_cve_markdown(r: CveReport) -> str:
    b, d = r.bundle, r.decision
    lines = [f"## {r.cve_id} — {d.headline}", ""]
    if r.discovered_by:
        lines += ["*Found by discovery:* " + "; ".join(r.discovered_by), ""]
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
    if b.cvss:
        from cveprio.cvss import explain_vector
        lines += ["### Severity score details", "", "| Source | CVSS version | Score | Rating | Evidence |", "|---|---|---|---|---|"]
        for c in b.cvss:
            used = " **(used)**" if b.primary_cvss and c.evidence_id == b.primary_cvss.evidence_id else ""
            lines.append(f"| {source_name(c.provider)}{used} | {c.version} | {c.base_score} | {(c.severity or '').capitalize()} "
                         f"| {c.evidence_id} |")
        if b.primary_cvss and b.primary_cvss.vector:
            lines += ["", f"What the {b.primary_cvss.base_score} score says: "
                      + "; ".join(f"{n}: {v}" for n, v in explain_vector(b.primary_cvss.vector))
                      + f" (`{b.primary_cvss.vector}`)", ""]
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
    out += [f"Provider `{llm.provider}`, model `{llm.model}`. Claims with valid citation IDs: "
            f"{llm.supported_claims}/{llm.total_claims} (cited IDs exist, but whether the source actually says what the claim says is NOT checked). Ratings are qualitative; no calibrated probability "
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
    if run.discovery:
        head += _render_discovery(run)
    return "\n".join(head + [render_cve_markdown(r) for r in run.reports])


def _render_discovery(run: RunReport) -> list[str]:
    d = run.discovery
    assert d is not None
    out = ["## CVE discovery", "",
           f"{d.total_found} candidate CVEs found from the inventory; {len(d.analyzed)} analysed below"
           + (f"; {len(d.dropped)} over the cap NOT analysed: {', '.join(d.dropped[:30])}"
              + (" …" if len(d.dropped) > 30 else "") if d.dropped else "") + ".", "",
           "| Asset | Software | Method | Status | CVEs found | Notes |", "|---|---|---|---|---|---|"]
    for q in d.queries:
        notes = q.detail or ""
        if q.non_cve_ids:
            notes += f" {len(q.non_cve_ids)} non-CVE advisories not analysed: {', '.join(q.non_cve_ids[:5])}"
        out.append(f"| {q.asset_id} | {_md_escape(q.product)} {_md_escape(q.version)} | {q.method} | {q.status} | "
                   f"{len(q.cve_ids)} | {_md_escape(notes.strip())} |")
    out += ["", "**Discovery limits:**", *[f"- {c}" for c in d.caveats], ""]
    return out


def write_outputs(run: RunReport, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"json": out_dir / "report.json", "markdown": out_dir / "report.md"}
    paths["json"].write_text(json.dumps(run.model_dump(mode="json"), indent=2))
    paths["markdown"].write_text(render_markdown(run))
    return paths
