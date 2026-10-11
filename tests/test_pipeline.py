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
