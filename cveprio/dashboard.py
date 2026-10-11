"""Static, self-contained HTML dashboard.

Security: all values (including untrusted advisory text) are rendered by Jinja2
with autoescaping; only http(s) URLs become links; a Content-Security-Policy
forbids any network access from the page. The only script is a small inline
filter/search helper that reads data attributes (no innerHTML).
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from cveprio.cvss import explain_vector, source_name
from cveprio.models import RunReport

STATUS = {
    "P1": ("critical", "▲"), "P2": ("serious", "◆"), "NEEDS_REVIEW": ("warning", "?"),
    "P3": ("neutral", "●"), "P4": ("muted", "○"), "NOT_APPLICABLE": ("good", "✓"),
    "NOT_IN_INVENTORY": ("good", "–"), "NO_ACTION_REJECTED": ("muted", "✕"),
    "INVALID_OR_UNPUBLISHED": ("muted", "∅"), "RETRIEVAL_FAILED": ("warning", "!"),
}
TILES = [("P1", "Act now"), ("P2", "Next patch cycle"), ("NEEDS_REVIEW", "Needs review"),
         ("P3", "Scheduled"), ("P4", "Backlog"), ("OTHER", "No action / not applicable")]


# Plain-English wording for readers who are not security specialists.
PLAIN_LABEL = {
    "P1": "Fix now", "P2": "Fix in the next patch cycle", "P3": "Schedule a fix", "P4": "Low priority",
    "NEEDS_REVIEW": "Check before deciding", "NOT_APPLICABLE": "Not affected — no action needed",
    "NOT_IN_INVENTORY": "Not installed here — no action needed", "NO_ACTION_REJECTED": "Cancelled CVE — no action needed",
    "INVALID_OR_UNPUBLISHED": "No public details yet — nothing to do", "RETRIEVAL_FAILED": "Data could not be loaded — try again",
}
PLAIN_FACTOR = {
    "exploitation": {
        "confirmed": "Attackers are known to be using it",
        "elevated": "Attack code is publicly claimed, or attacks are likely soon",
        "low_observed": "No sign of attacks found (not proof it is safe)",
        "evidence_incomplete": "Could not check for attacks (a source failed)",
        "n/a": "Not applicable",
    },
    "severity": {
        "critical": "Critical (CVSS 9–10)", "high": "High (CVSS 7–8.9)", "medium": "Medium (CVSS 4–6.9)",
        "low": "Low (CVSS below 4)", "unscored": "Not scored yet", "n/a": "Not applicable",
    },
    "exposure": {
        "high": "An affected system is internet-facing or business-critical",
        "standard": "Affected systems are internal and of normal importance",
        "context_unknown": "Affected, but how exposed/important the system is was not recorded",
        "reduced": "Affected, but a protection (e.g. firewall rule) limits access",
        "not_assessed": "Unknown — no list of your software was given",
        "needs_review": "Unclear whether your version is affected",
        "not_affected": "Your installed version is not affected",
        "not_in_inventory": "This software is not in your inventory",
        "n/a": "Not applicable",
    },
}
SHORT_FACTOR = {
    "exploitation": {"confirmed": "actively attacked", "elevated": "exploit claimed / likely", "low_observed": "no attack signs",
                     "evidence_incomplete": "attack data missing", "n/a": "n/a"},
    "exposure": {"high": "exposed or critical system", "standard": "internal system", "context_unknown": "context missing",
                 "reduced": "protected by a control", "not_assessed": "no inventory", "needs_review": "version unclear",
                 "not_affected": "not affected", "not_in_inventory": "not installed", "n/a": "n/a"},
}
_CITE = re.compile(r"\s*\[((?:CVE|NVD|KEV|EPSS)[A-Za-z0-9.]*(?:,\s*(?:CVE|NVD|KEV|EPSS)[A-Za-z0-9.]*)*)\]")


def split_cites(text: str) -> tuple[str, list[str]]:
    """Move evidence tags like '[KEV, NVD.ref.1]' out of a sentence so they can be shown as small labels."""
    ids: list[str] = []
    for m in _CITE.finditer(text):
        ids.extend(x.strip() for x in m.group(1).split(","))
    return _CITE.sub("", text).strip(), list(dict.fromkeys(ids))


def split_item(text: str) -> tuple[str, str, list[str]]:
    """'SHORT — DETAILS [ids]' -> (short, details, ids). See report.SEP."""
    body, ids = split_cites(text)
    short, _, detail = body.partition(" — ")
    return short.strip(), detail.strip(), ids


REASON_EXPLOIT = {"confirmed": "attackers are using it", "elevated": "attack code is public or attacks are likely",
                  "low_observed": "there is no sign of attacks", "evidence_incomplete": "attack data is missing"}
REASON_EXPOSURE = {"high": "it is on an exposed or critical system", "standard": "it is only on internal systems",
                   "context_unknown": "details about the affected system are missing",
                   "reduced": "a protection limits access to it", "needs_review": "it is unclear whether your version is affected",
                   "not_affected": "your installed version is not affected",
                   "not_in_inventory": "you don't run this software"}


def compare_reason(factors: dict[str, str]) -> str:
    """Plain 'because …' clause for the score-only comparison."""
    x = factors.get("exposure", "")
    if x in ("needs_review", "not_affected", "not_in_inventory"):
        return REASON_EXPOSURE[x]
    parts = [REASON_EXPLOIT.get(factors.get("exploitation", ""), ""), REASON_EXPOSURE.get(x, "")]
    return " and ".join(p for p in parts if p)


def why_sentence(factors: dict[str, str]) -> str:
    e, x = factors.get("exploitation", "n/a"), factors.get("exposure", "n/a")
    if e == "n/a":
        return ""
    return f"{PLAIN_FACTOR['exploitation'].get(e, e)}. {PLAIN_FACTOR['exposure'].get(x, x)}."


def _safe_url(url: str | None) -> str | None:
    return url if url and url.startswith(("https://", "http://")) else None


def render_dashboard(run: RunReport) -> str:
    env = Environment(loader=PackageLoader("cveprio", "templates"), autoescape=select_autoescape(["html", "j2"]),
                      trim_blocks=True, lstrip_blocks=True)
    env.filters["safe_url"] = _safe_url
    env.filters["split_cites"] = split_cites
    env.filters["split_item"] = split_item
    env.filters["explain_vector"] = explain_vector
    env.filters["source_name"] = source_name
    env.globals.update(compare_reason=compare_reason, PLAIN_LABEL=PLAIN_LABEL, PLAIN_FACTOR=PLAIN_FACTOR, SHORT_FACTOR=SHORT_FACTOR,
                       why_sentence=why_sentence)
    counts = Counter(r.decision.label for r in run.reports)
    tiles = [(k, label, counts.get(k, 0) if k != "OTHER" else
              sum(v for lab, v in counts.items() if lab not in {"P1", "P2", "P3", "P4", "NEEDS_REVIEW"}))
             for k, label in TILES]
    differs = [r for r in run.reports if r.decision.baseline_label != "N/A"
               and r.decision.label != r.decision.baseline_label]
    return env.get_template("dashboard.html.j2").render(run=run, tiles=tiles, status=STATUS, differs=differs)


def write_dashboard(run: RunReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_dashboard(run))
    return path
