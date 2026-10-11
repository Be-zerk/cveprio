"""Report text: known / uncertain lists, and Markdown rendering.

Every bullet carries evidence IDs in brackets; the Evidence table at the end of
each report maps IDs to source URL, retrieval time and dates. AI content is in a
separate, labelled section and never mixed into "What is known".
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from cveprio.cvss import cwe_name, cwe_short, source_name
from cveprio.models import (
    ApplicabilityResult,
    ApplicabilityStatus,
    CveReport,
    Decision,
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
    "disputed": "Disputed as a real vulnerability",
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


def _plain_source(src: str) -> str:
    src = src.strip()
    if src.startswith("CNA:"):
        org = src[4:].split(" '")[0]
        return f"{org}'s CVE record"
    if src.startswith("ADP:"):
        return "CISA's additions to the CVE record" if "CISA" in src else f"{src[4:].split(' ')[0]}'s additions"
    if src.startswith("NVD"):
        return "NVD"
    return src


def _plain_range(text: str) -> str:
    def nvd(m: re.Match[str]) -> str:
        b = dict((s, v) for s, v in re.findall(r"(≥|>|≤|<)(\S+)", m.group(1)))
        lo = f"{b['≥']}" if "≥" in b else (f"after {b['>']}" if ">" in b else "")
        if "<" in b:
            hi_txt = f"up to (not including) {b['<']}" if lo else f"before {b['<']}"
        elif "≤" in b:
            hi_txt = f"up to and including {b['≤']}"
        else:
            hi_txt = "and later" if lo else ""
        return f"versions {lo} {hi_txt} are affected".replace("  ", " ")
    text = re.sub(r"in range ((?:(?:≥|>|≤|<)\S+ ?)+)$", nvd, text)
    text = re.sub(r"in range 0\.\.<(\S+) → affected", r"versions before \1 are affected", text)
    text = re.sub(r"in range (\S+?)\.\.<(\S+) → affected", r"versions \1 up to (not including) \2 are affected", text)
    text = re.sub(r"in range (\S+?)\.\.≤(\S+) → affected", r"versions \1 up to and including \2 are affected", text)
    text = re.sub(r"in range (\S+?)\.\.[<≤]?(\S+) → unaffected", r"versions \1 to \2 are listed as not affected", text)
    return text


def plain_reason(line: str) -> str:
    """'[affected] CNA:redhat 'OpenSSH': name 'openssh': in range 8.5p1..≤9.7p1 → affected' -> a sentence."""
    m = re.match(r"\[(affected|not_affected|ambiguous)\] (.+?): (.*)$", line)
    if not m:
        if line.startswith("No exact product match"):
            return ("The product name in your inventory does not exactly match any affected product in this CVE; "
                    "a similar name is not proof you are affected")
        sim = re.match(r"^(CNA|ADP):(\S+): similar name: '([^']+)' vs '([^']+)'", line)
        if sim:
            return f"{sim.group(2)}'s CVE record lists '{sim.group(4)}', which only resembles your '{sim.group(3)}'"
        ven = re.match(r"^(CNA|ADP):(\S+): name '([^']+)' matches but vendor differs \((.+)\)", line)
        if ven:
            return f"{ven.group(2)}'s CVE record lists the same name '{ven.group(3)}' but a different vendor ({ven.group(4)})"
        cpe = re.match(r"^NVD CPE (\S+) resembles (\S+)", line)
        if cpe:
            return f"NVD lists {cpe.group(1)}, which resembles your {cpe.group(2)}"
        return line.replace("Sources disagree for this version:", "The sources disagree about this version").rstrip(":")
    _, src, rest = m.groups()
    rest = re.sub(r"^(name '[^']*'|CPE [^:]+:[^:]+|similar name[^:]*): ", "", rest)
    if "AND configuration" in rest:
        other = re.search(r"cpe:2\.3:\w:([^:]+):([^:]+)", rest)
        name = " ".join(w.upper() if len(w) <= 3 else w.capitalize()
                        for w in f"{other.group(1)} {other.group(2)}".replace("_", " ").split()) if other else ""
        rest = _plain_range(rest.split(";")[0]) + (f", but only together with {name}" if name else "")
    rest = _plain_range(rest)
    rest = re.sub(r"version not listed; source default status is 'unaffected'",
                  "your version is not listed, and the record marks unlisted versions as not affected", rest)
    rest = re.sub(r"version not listed; source default status is 'affected'",
                  "your version is not listed, and the record marks unlisted versions as affected", rest)
    rest = re.sub(r"version (\S+) outside all (\d+) NVD ranges", r"version \1 is outside all \2 affected ranges", rest)
    rest = re.sub(r"cannot compare '([^']+)' with .*", r"version \1 could not be compared with the listed versions "
                  "automatically", rest)
    rest = re.sub(r"matches free-text constraint '([^']+)' \(parsed as [^)]*\)", r"the record says '\1', which "
                  "includes your version", rest)
    rest = re.sub(r"malformed range in source: .*", "the record's version range contains an error", rest)
    rest = re.sub(r"exact (?:CPE )?version (\S+)(?: → affected)?", r"version \1 is listed as affected", rest)
    rest = re.sub(r"upper bound '([^']+)' is not a comparable version", r"its upper version limit ('\1') is not a "
                  "normal version number", rest)
    rest = rest.replace("OSV lists", "lists").replace(" → affected", "")
    return f"{_plain_source(src)}: {rest}"


def _plain_reasons(reasons: list[str]) -> str:
    return " ".join(plain_reason(x).rstrip(".") + "." for x in reasons if x.strip())


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
        detail = _plain_reasons(r.reasons)
        if r.status == ApplicabilityStatus.AFFECTED:
            known.append(item(f"{who} is affected", detail, r.evidence_ids))
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


def _pct(p: float) -> str:
    return ">99.9%" if p >= 0.9995 else "<0.1%" if p < 0.0005 else f"{p * 100:.1f}%"


def _asset_context(r: ApplicabilityResult) -> str:
    bits = []
    if r.asset_internet_facing is True:
        bits.append("internet-facing")
    elif r.asset_internet_facing is False:
        bits.append("internal")
    if r.asset_criticality:
        bits.append(f"{r.asset_criticality} importance")
    if r.asset_internet_facing is None or r.asset_criticality is None:
        missing = [w for w, v in (("internet exposure", r.asset_internet_facing), ("importance", r.asset_criticality))
                   if v is None]
        bits.append(" and ".join(missing) + " not recorded")
    text = ", ".join(bits)
    if r.asset_controls:
        text += "; protected by: " + "; ".join(r.asset_controls) + " (not checked by this tool)"
    return text


def _list_assets(rs: list[ApplicabilityResult], limit: int = 3) -> str:
    parts = [f"{r.asset_id} ({r.software.product} {r.software.version}) — {_asset_context(r)}" for r in rs[:limit]]
    more = f"; and {len(rs) - limit} more" if len(rs) > limit else ""
    return "; ".join(parts) + more


def explain_decision(bundle: EvidenceBundle, results: list[ApplicabilityResult], decision: Decision,
                     llm: LlmAnalysis | None = None) -> list[str]:
    """1–3 plain sentences saying, for THIS CVE and YOUR systems, why the decision came out as it did."""
    if bundle.record_state == RecordState.REJECTED:
        return ["This CVE was cancelled (rejected) by the organisation that issued it, so there is nothing to fix."]
    if bundle.record_state == RecordState.RESERVED:
        return ["This CVE number has been reserved, but no details have been published yet."]
    if bundle.record_state == RecordState.NOT_FOUND:
        return ["No CVE record exists for this number. Check it for typos."]
    if bundle.record_state != RecordState.PUBLISHED:
        return ["The CVE record could not be loaded from any source, so no recommendation can be made."]

    out: list[str] = []
    e = decision.factors.get("exploitation")
    kev = bundle.get("KEV")
    epss = bundle.epss
    claimed = bundle.findings.get("public_exploit_claimed")
    n_refs = len([i for i in (claimed.evidence_ids if claimed else []) if ".ref" in i])
    ssvc = bundle.ssvc
    if e == "confirmed":
        parts = []
        if kev and kev.kind == "kev_entry":
            parts.append(f"it is on CISA's list of actively attacked flaws (added {kev.fields.get('dateAdded')})")
        if ssvc and ssvc.exploitation == "active":
            parts.append("CISA rates exploitation as active")
        out.append("Attackers are known to be using it: " + ", and ".join(parts) + ".")
    elif e == "elevated":
        parts = []
        if ssvc and ssvc.exploitation in ("poc", "active"):
            parts.append("CISA says demo attack code exists")
        if n_refs:
            parts.append(f"{n_refs} public source{'s point' if n_refs != 1 else ' points'} to attack code")
        if epss and epss.probability >= 0.10:
            parts.append(f"the predicted chance of attacks in the next 30 days is {_pct(epss.probability)}")
        if not parts:
            parts.append("the AI assessment rates it easy to exploit (cited and validated)")
        out.append("Attacks are likely: " + "; ".join(parts) + ". No confirmed attacks are on record.")
    elif e == "claimed_unverified":
        ids = claimed.evidence_ids if claimed else []
        where = " and ".join(w for w, pre in (("NVD", "NVD.ref"), ("the CVE record", "CVE.ref"))
                             if any(i.startswith(pre) for i in ids)) or "NVD"
        bits = [f"{n_refs} source{'s' if n_refs != 1 else ''} tagged as attack code by {where}"]
        if epss:
            bits.append(f"the predicted chance of attacks in the next 30 days is only {_pct(epss.probability)}")
        out.append("Attack code may be public, but this is unconfirmed: " + "; ".join(bits)
                   + ". There is no CISA rating of demo attack code and no known attacks.")
    elif e == "low_observed":
        bits = ["it is not on CISA's attacked list", "no public attack code was found"]
        if epss:
            bits.append(f"the predicted chance of attacks in the next 30 days is {_pct(epss.probability)}")
        out.append("No sign of attacks so far: " + "; ".join(bits) + ". This is not proof it is safe.")
    elif e == "evidence_incomplete":
        failed = [s.source.value for s in bundle.sources if s.status in (SourceStatus.FAILED, SourceStatus.RATE_LIMITED)]
        out.append("Attack activity could not be checked because these sources failed: " + ", ".join(failed) + ".")

    x = decision.factors.get("exposure")
    affected = [r for r in results if r.status == ApplicabilityStatus.AFFECTED]
    review = [r for r in results if r.status == ApplicabilityStatus.NEEDS_REVIEW]
    not_aff = [r for r in results if r.status == ApplicabilityStatus.NOT_AFFECTED]
    if affected:
        out.append("It affects " + _list_assets(affected) + ".")
    elif x == "needs_review" and review:
        r = review[0]
        others = f" {len(review) - 1} other system{'s' if len(review) > 2 else ''} also need a check." if len(review) > 1 else ""
        out.append(f"It is unclear whether {r.asset_id}'s {r.software.product} {r.software.version} is affected: "
                   f"{_review_reason(r)}{others}")
    elif x == "not_affected" and not_aff:
        names = ", ".join(f"{r.asset_id}'s {r.software.product} {r.software.version}" for r in not_aff[:3])
        out.append(f"Your installed version is outside the affected versions: {names}.")
    elif x == "not_in_inventory":
        out.append("None of the software in your inventory matches this CVE's affected products.")
    elif x == "not_assessed":
        out.append("No software list was given, so it is unknown whether you run the affected product.")
    if affected and review:
        names = ", ".join(sorted({r.asset_id for r in review}))
        out.append(f"Also check {names}: it may be affected too, but this could not be confirmed automatically.")
    if x in ("not_affected", "not_in_inventory") and len(out) > 1:
        attack = out.pop(0)
        attack = (attack[0].lower() + attack[1:]).replace(": ", " — ", 1)
        out.append("For reference (it does not change the decision): " + attack)
    return out


def _review_reason(r: ApplicabilityResult) -> str:
    """Plain-language reason why a version check is needed."""
    text = " ".join(r.reasons)
    if "AND configuration" in text:
        m = re.search(r"cpe:2\.3:\w:([^:]+):([^:]+)", text.split("combination with", 1)[-1])
        words = f"{m.group(1)} {m.group(2)}".replace("_", " ").split() if m else []
        other = " ".join(w.upper() if len(w) <= 3 else w.capitalize() for w in words) or "another product"
        return (f"its version is in the affected range, but the flaw only applies together with {other}, "
                "which your inventory does not record.")
    if "backport" in text:
        return ("it is a Linux distribution package; distributions often fix flaws without changing the version "
                "number, so check the distribution's security advisory.")
    if "similar" in text:
        return "the name in your inventory only resembles the affected product, and the exact version is not known."
    if "disagree" in text:
        return "the data sources disagree about whether this version is affected."
    if "malformed range" in text:
        return "the source's list of affected versions contains an error, so it cannot be checked automatically."
    return "the version information could not be compared automatically."


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
        *([f"**In short:** {' '.join(r.summary)}", ""] if r.summary else []),
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
