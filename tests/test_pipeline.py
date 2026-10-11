"""End-to-end (offline): AC17, AC20–AC22, plus CLI behaviour."""

from __future__ import annotations

import json
import os

import pytest

from cveprio.cli import main
from cveprio.config import DEFAULT_FIXTURES, Settings
from cveprio.models import Inventory, SourceStatus
from cveprio.net import FetchError, FixtureFetcher
from cveprio.pipeline import Runtime, make_runtime, run
from cveprio.report import render_markdown
from tests.conftest import project_root

INVENTORY = project_root() / "examples" / "inventory.json"


@pytest.fixture(scope="module")
def demo_run():
    rt = make_runtime(Settings(), offline=True, provider_name="scripted")
    inv = Inventory.model_validate_json(INVENTORY.read_text())
    return run(inv.watchlist, rt, inv)


def test_demo_expected_decisions(demo_run):
    got = {r.cve_id: r.decision.label for r in demo_run.reports}
    assert got == {
        "CVE-2021-44228": "P1", "CVE-2023-44487": "P1", "CVE-2024-6387": "P1", "CVE-2023-38545": "P2",
        "CVE-2022-22965": "NEEDS_REVIEW", "CVE-2024-47176": "P3", "CVE-2024-3094": "NOT_APPLICABLE",
        "CVE-2026-11415": "NO_ACTION_REJECTED", "CVE-2026-99001": "INVALID_OR_UNPUBLISHED",
    }


def test_every_report_has_required_sections(demo_run):
    md = render_markdown(demo_run)
    for r in demo_run.reports:
        assert r.known, r.cve_id
        assert r.decision.trace and r.decision.actions
    for heading in ("What is known", "What remains uncertain", "Why this priority", "Action supported",
                    "What would change"):
        assert md.count(heading) == len(demo_run.reports)


def test_report_citations_resolve(demo_run):
    import re
    for r in demo_run.reports:
        ids = r.bundle.evidence_ids()
        for line in r.known + r.uncertain + r.decision.actions:
            for group in re.findall(r"\[([A-Za-z0-9., ]+)\]", line):
                for ref in (x.strip() for x in group.split(",")):
                    if re.match(r"^(CVE|NVD|KEV|EPSS)", ref):
                        assert ref in ids, (r.cve_id, ref, line)


def test_demo_clearly_labelled_everywhere(demo_run):
    assert demo_run.mode == "offline_demo" and "OFFLINE DEMO" in demo_run.notices[0]
    assert all(e.demo for r in demo_run.reports for e in r.bundle.evidence)
    md = render_markdown(demo_run)
    assert "OFFLINE DEMO" in md and "FICTIONAL" in md and "SCRIPTED EXAMPLE" in md


def test_degraded_run_is_visible_not_filled_in():
    class Flaky(FixtureFetcher):
        demo = False

        def get(self, url, **kw):
            if "nvd.nist.gov" in url:
                raise FetchError("rate_limited", "HTTP 429 (simulated)")
            return super().get(url, **kw)

    rt = Runtime(fetcher=Flaky(DEFAULT_FIXTURES), provider=make_runtime(Settings(), offline=True).provider,
                 settings=Settings(), offline=False)
    r = run(["CVE-2024-6387"], rt).reports[0]
    assert any(s.status == SourceStatus.RATE_LIMITED for s in r.bundle.sources)
    assert any("Partial result" in u for u in r.uncertain)
    assert not any(e.source.value == "nvd" for e in r.bundle.evidence)  # nothing fabricated for NVD
    from cveprio.dashboard import render_dashboard
    html = render_dashboard(run(["CVE-2024-6387"], rt))
    assert "source lookups failed or were rate-limited" in html and "NVD: rate limited" in html


def test_cli_demo_writes_outputs_and_no_secrets(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NVD_API_KEY", "nvd-SECRET-should-not-leak")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-SECRET-should-not-leak")
    out = tmp_path / "demo"
    assert main(["demo", "--out", str(out)]) == 0
    printed = capsys.readouterr().out
    for f in ("report.json", "report.md", "dashboard.html"):
        text = (out / f).read_text()
        assert "SECRET-should-not-leak" not in text, f
    assert "SECRET-should-not-leak" not in printed
    data = json.loads((out / "report.json").read_text())
    assert data["mode"] == "offline_demo" and data["fictional_context"] is True


def test_cli_invalid_id_exit_code(capsys):
    assert main(["analyze", "CVE-21-1", "--offline"]) == 2


def test_cli_scripted_provider_refused_in_live_mode(capsys):
    assert main(["analyze", "CVE-2021-44228", "--llm", "scripted"]) == 2


def test_settings_repr_masks_secrets(monkeypatch):
    s = Settings(nvd_api_key="abc123secret", anthropic_api_key="sk-ant-xyz")
    assert "abc123secret" not in repr(s) and "sk-ant-xyz" not in str(s) and "***set***" in repr(s)


def test_repository_contains_no_obvious_secrets():
    root = project_root()
    import re
    pat = re.compile(r"(sk-ant-[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})")
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".venv", ".git", ".cache", "out", "__pycache__",
                                                        ".mypy_cache", ".ruff_cache", ".pytest_cache"}]
        for f in files:
            p = os.path.join(dirpath, f)
            if f.endswith((".py", ".json", ".md", ".toml", ".example", ".txt", ".html", ".j2")) and f != "test_pipeline.py":
                assert not pat.search(open(p, errors="ignore").read()), p


def test_dashboard_escapes_untrusted_text_and_blocks_network():
    from cveprio.dashboard import render_dashboard
    from cveprio.llm.providers import NoProvider
    from tests.conftest import cve5_record, synthetic_fetcher
    evil = '<script>alert(1)</script><img src=x onerror=alert(2)> <a href="javascript:alert(3)">x</a>'
    f = synthetic_fetcher("CVE-1999-99001", record=cve5_record("CVE-1999-99001", description=evil))
    rt = Runtime(fetcher=f, provider=NoProvider(), settings=Settings(), offline=False)
    html = render_dashboard(run(["CVE-1999-99001"], rt))
    assert "<script>alert(1)" not in html and "<img src=x" not in html
    assert "&lt;script&gt;alert(1)" in html
    assert 'href="javascript:' not in html
    assert "default-src 'none'" in html


def test_cvss_vector_explained_in_plain_words():
    from cveprio.cvss import explain_vector
    got = dict(explain_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"))
    assert got["Attack from"].startswith("the network") and got["Login / privileges needed"] == "none"
    assert dict(explain_vector("AV:N/AC:M/Au:N/C:P/I:P/A:P"))["Authentication needed"] == "none"  # CVSS v2
    assert explain_vector(None) == []


def test_summary_is_specific_to_cve_and_systems(demo_run):
    by_id = {r.cve_id: " ".join(r.summary) for r in demo_run.reports}
    assert "2021-12-10" in by_id["CVE-2021-44228"] and "web-portal-01" in by_id["CVE-2021-44228"]
    assert "internet-facing" in by_id["CVE-2021-44228"]
    assert "Oracle JDK" in by_id["CVE-2022-22965"] and "cpe:2.3" not in by_id["CVE-2022-22965"]
    assert by_id["CVE-2024-3094"].startswith("Your installed version is outside")  # not-affected leads
    assert "not recorded" in by_id["CVE-2023-38545"]  # missing context named, not assumed
    assert "cancelled" in by_id["CVE-2026-11415"]


def test_factor_boxes_name_real_systems_and_evidence(demo_run):
    from cveprio.dashboard import factor_cards
    cards = {r.cve_id: dict(factor_cards(r)) for r in demo_run.reports}
    log4j = cards["CVE-2021-44228"]
    assert "2021-12-10" in log4j["Attack activity"] and "10.0 out of 10" in log4j["Severity on paper"]
    assert log4j["Your exposure"] == "web-portal-01 is internet-facing and high importance"
    assert "dev-laptop-17" in cards["CVE-2023-38545"]["Your exposure"]
    assert "print-srv-01" in cards["CVE-2024-47176"]["Your exposure"]
    generic = "An affected system is internet-facing or business-critical"
    assert all(generic not in c["Your exposure"] for c in cards.values())


def test_dashboard_visible_text_has_no_rule_codes(demo_run):
    """Everything shown without opening a collapsed section must be plain language."""
    import re
    from html.parser import HTMLParser

    from cveprio.dashboard import render_dashboard

    class Visible(HTMLParser):
        def __init__(self):
            super().__init__()
            self.stack, self.text = [], []

        def handle_starttag(self, tag, attrs):
            classes = dict(attrs).get("class", "") or ""
            # inner <details> (not the CVE cards) are collapsed; <script>/<style>/<code> are not prose
            hide = (tag == "details" and "cve" not in classes) or tag in ("script", "style", "summary-raw")
            self.stack.append((tag, hide))

        def handle_endtag(self, tag):
            while self.stack:
                t, _ = self.stack.pop()
                if t == tag:
                    break

        def handle_data(self, data):
            if not any(h for _, h in self.stack):
                self.text.append(data)

    p = Visible()
    p.feed(render_dashboard(demo_run))
    visible = " ".join(p.text)
    codes = re.findall(r"\b(low_observed|claimed_unverified|context_unknown|not_assessed|needs_review|not_affected|"
                       r"not_in_inventory|evidence_incomplete|insufficient_evidence|public_exploit_claimed|"
                       r"NOT_APPLICABLE|NEEDS_REVIEW|NO_ACTION_REJECTED|INVALID_OR_UNPUBLISHED|offline_demo)\b", visible)
    assert not codes, sorted(set(codes))


def test_missing_records_are_not_presented_as_safe(demo_run):
    """Reserved / unloadable records: no priority, but never 'nothing uncertain' or 'no action needed'."""
    from cveprio.dashboard import group_of, render_dashboard

    class Down(FixtureFetcher):
        demo = False

        def get(self, url, **kw):
            if "cveawg.mitre.org" in url or "nvd.nist.gov" in url:
                raise FetchError("network", "down (simulated)")
            return super().get(url, **kw)

    rt = Runtime(fetcher=Down(DEFAULT_FIXTURES), provider=make_runtime(Settings(), offline=True).provider,
                 settings=Settings(), offline=False)
    failed = run(["CVE-2024-6387"], rt).reports[0]
    reserved = next(r for r in demo_run.reports if r.bundle.record_state.value == "reserved")
    rejected = next(r for r in demo_run.reports if r.bundle.record_state.value == "rejected")
    for r, label in ((failed, "RETRIEVAL_FAILED"), (reserved, "INVALID_OR_UNPUBLISHED")):
        assert r.decision.label == label and r.decision.priority is None
        assert r.uncertain, f"{label}: missing data must be listed as uncertain"
        assert r.decision.counterfactuals
        assert group_of(label) == "UNKNOWN"
    assert group_of(rejected.decision.label) == "OTHER"
    html = render_dashboard(demo_run)
    assert "Cannot assess yet" in html and "nothing to do" not in html.lower()


def test_ai_status_shown_in_plain_words(demo_run):
    from cveprio.dashboard import render_dashboard
    html = render_dashboard(demo_run)
    assert "No AI assessment</b>: No scripted example" in html and "AI assessment not run</b>: Record is reserved" in html
    assert "<b>not_configured</b>" not in html and "<b>skipped</b>" not in html
