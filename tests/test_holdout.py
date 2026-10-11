"""Held-out set: selection helpers, the labelling sheet and how labels reach the evaluation."""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

from cveprio.config import PROJECT_ROOT, Settings
from cveprio.evaluation import run_evaluation
from cveprio.holdout import LABEL_COLUMNS, _item_from_nvd, write_labeling

HOLDOUT = PROJECT_ROOT / "evaluation" / "holdout"


def nvd(criteria, **rng):
    return {"configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": criteria, **rng}]}]}]}


def test_affected_side_uses_first_affected_version():
    item = _item_from_nvd(nvd("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", versionStartIncluding="2.0",
                              versionEndExcluding="2.4"), want_affected=True)
    assert item and item["version"] == "2.0" and item["cpe"].split(":")[5] == "2.0"


def test_fixed_side_uses_first_fixed_version():
    item = _item_from_nvd(nvd("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", versionEndExcluding="2.4"), want_affected=False)
    assert item and item["version"] == "2.4"


def test_no_usable_version_gives_none():
    assert _item_from_nvd(nvd("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"), want_affected=True) is None


def test_committed_holdout_is_unlabelled():
    """Labels must come from a human; the tool never fills them in itself."""
    spec = json.loads((HOLDOUT / "cases.json").read_text())
    assert len(spec["cases"]) == 20
    assert all(not c["expected_applicability"] and not c["acceptable_decisions"] for c in spec["cases"])
    assert any(c["pool"].startswith("PKG") for c in spec["cases"])


def test_labeling_sheet_has_one_row_per_case(tmp_path):
    cases = json.loads((HOLDOUT / "cases.json").read_text())["cases"]
    write_labeling(cases, tmp_path)
    rows = list(csv.DictReader((tmp_path / "labels.csv").open()))
    assert [r["id"] for r in rows] == [c["id"] for c in cases]
    assert list(rows[0].keys()) == LABEL_COLUMNS
    assert all(not r["expected_applicability"] for r in rows)
    guide = (tmp_path / "LABELING.md").read_text()
    assert "before you run the evaluation" in guide and cases[0]["cve_id"] in guide


def test_unlabelled_cases_are_skipped_and_labels_csv_is_used(tmp_path):
    copy = tmp_path / "holdout"
    shutil.copytree(HOLDOUT, copy)
    sheet = copy / "labels.csv"
    rows = list(csv.DictReader(sheet.open()))
    rows[0].update(expected_applicability="no_product_match", acceptable_decisions="P1, P2", rationale="test")
    with sheet.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=LABEL_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    md = run_evaluation(Settings(), provider_name="none", out_dir=tmp_path / "out", cases_path=copy / "cases.json",
                        fixtures=copy / "fixtures", tag="holdout")
    result = json.loads(Path(str(md).replace(".md", ".json")).read_text())
    assert result["unlabelled_cases_skipped"] == 19
    assert [c["id"] for c in result["cases"]] == ["h01"]
    assert "Labels come from one person" in Path(md).read_text()
