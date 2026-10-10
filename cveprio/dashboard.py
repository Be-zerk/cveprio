"""Static, self-contained HTML dashboard.

Security: all values (including untrusted advisory text) are rendered by Jinja2
with autoescaping; only http(s) URLs become links; a Content-Security-Policy
forbids any network access from the page. The only script is a small inline
filter/search helper that reads data attributes (no innerHTML).
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from cveprio.models import RunReport

STATUS = {
    "P1": ("critical", "▲"), "P2": ("serious", "◆"), "NEEDS_REVIEW": ("warning", "?"),
    "P3": ("neutral", "●"), "P4": ("muted", "○"), "NOT_APPLICABLE": ("good", "✓"),
    "NOT_IN_INVENTORY": ("good", "–"), "NO_ACTION_REJECTED": ("muted", "✕"),
    "INVALID_OR_UNPUBLISHED": ("muted", "∅"), "RETRIEVAL_FAILED": ("warning", "!"),
}
TILES = [("P1", "Act now"), ("P2", "Next patch cycle"), ("NEEDS_REVIEW", "Needs review"),
         ("P3", "Scheduled"), ("P4", "Backlog"), ("OTHER", "No action / not applicable")]


def _safe_url(url: str | None) -> str | None:
    return url if url and url.startswith(("https://", "http://")) else None


def render_dashboard(run: RunReport) -> str:
    env = Environment(loader=PackageLoader("cveprio", "templates"), autoescape=select_autoescape(["html", "j2"]),
                      trim_blocks=True, lstrip_blocks=True)
    env.filters["safe_url"] = _safe_url
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
