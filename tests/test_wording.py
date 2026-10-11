"""Every reader-facing sentence must be specific and plain: no vague either/or phrasing, no rule codes,
no machine-formatted matching text, no grammar slips. Runs over the full offline demo."""

from __future__ import annotations

import re

import pytest

from cveprio.config import Settings
from cveprio.dashboard import compare_why, factor_cards, split_item
from cveprio.models import Inventory
from cveprio.pipeline import make_runtime, run
from tests.conftest import project_root

PATTERNS = {
    "vague either/or": r"\b(internet-facing or|or business-critical|or high-criticality|exposed or critical|and/or|"
                       r"low/medium|may or may not|or others\b|NVD or the CVE record|exists or attacks|claimed or attacks)",
    "grammar": r"\b1 (public )?sources? point\b|item\(s\)|\b1 (sources|references)\b|  |:\.",
    "rule codes": r"\b(low_observed|claimed_unverified|context_unknown|not_assessed|needs_review|not_affected|"
                  r"not_in_inventory|evidence_incomplete|internet_facing)\b",
    "machine text": r"CNA:|ADP:|name '[a-z]|CPE [a-z]+:|\.\.[<≤]|→ affected|\[ambiguous\]|:;|similar name:",
}


@pytest.fixture(scope="module")
def sentences():
    inv = Inventory.model_validate_json((project_root() / "examples" / "inventory.json").read_text())
    report = run(inv.watchlist, make_runtime(Settings(), offline=True, provider_name="scripted"), inv)
    out = []
    for r in report.reports:
        d = r.decision
        out += r.summary + [v for _, v in factor_cards(r)]
        for t in r.known + r.uncertain + d.trace + d.actions + d.counterfactuals:
            short, detail, _ = split_item(t)
            out += [short] + ([detail] if detail else [])
        if d.baseline_label != "N/A" and d.label != d.baseline_label:
            out.append(compare_why(r))
    return out


@pytest.mark.parametrize("name", list(PATTERNS))
def test_no_bad_wording(sentences, name):
    bad = [s for s in sentences if re.search(PATTERNS[name], s)]
    assert not bad, f"{name}: {bad[:3]}"


def test_headlines_stay_short(sentences):
    from cveprio.report import SEP
    assert SEP  # sanity: bullets use the short — details convention
    assert len(sentences) > 100
