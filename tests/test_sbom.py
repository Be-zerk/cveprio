"""SBOM import: CycloneDX (real file from cyclonedx-py) and SPDX 2.3, untrusted-input handling."""

from __future__ import annotations

import json
import os

import pytest

from cveprio.applicability import assess
from cveprio.models import ApplicabilityStatus, Inventory, SoftwareItem
from cveprio.sbom import SbomError, attach_sboms, inventory_from_sboms, load_sbom
from tests.conftest import project_root, synthetic_bundle

EX = project_root() / "examples"


def test_real_cyclonedx_from_official_tool():
    res = load_sbom(EX / "sbom" / "cveprio-python-env.cdx.json")
    assert res.format == "CycloneDX 1.6" and len(res.items) >= 30
    jinja = next(i for i in res.items if i.product == "Jinja2")
    assert jinja.purl == "pkg:pypi/jinja2@3.1.6" and jinja.version == "3.1.6"


def test_cyclonedx_skips_non_software_and_reports_it():
    res = load_sbom(EX / "sbom" / "shipment-tracker.cdx.json")
    assert res.subject == "shipment-tracker"
    assert {i.product for i in res.items} >= {"log4j-core", "commons-text", "snakeyaml"}
    assert any("application.yml" in s[0] and "not software" in s[1] for s in res.skipped)
    assert "skipped" in res.describe()


def test_spdx_purl_cpe_supplier_and_missing_version():
    res = load_sbom(EX / "sbom" / "warehouse-gateway.spdx.json")
    assert res.format == "SPDX-2.3"
    curl = next(i for i in res.items if i.product == "curl")
    assert curl.cpe == "cpe:2.3:a:haxx:libcurl:8.3.0:*:*:*:*:*:*:*" and curl.vendor == "curl project"
    req = next(i for i in res.items if i.product == "requests")
    assert req.purl == "pkg:pypi/requests@2.25.1" and req.vendor is None  # NOASSERTION is not a vendor
    assert ("internal-tool", "no version") in res.skipped


def test_nested_cyclonedx_components_and_dedupe(tmp_path):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "a", "version": "1.0", "purl": "pkg:npm/a@1.0",
         "components": [{"type": "library", "name": "b", "version": "2.0"}]},
        {"type": "library", "name": "a", "version": "1.0", "purl": "pkg:npm/a@1.0"},
        {"type": "library", "name": "noversion"}]}
    p = tmp_path / "x.json"
    p.write_text(json.dumps(doc))
    res = load_sbom(p)
    assert [i.product for i in res.items] == ["a", "b"]
    assert ("noversion", "no version") in res.skipped


@pytest.mark.parametrize("content,msg", [
    ("<?xml version='1.0'?><bom/>", "XML"),
    ("{not json", "not valid JSON"),
    ('{"hello": "world"}', "not a recognised SBOM"),
    ('{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}', "SPDX 3"),
    ("[1, 2]", "JSON object"),
])
def test_bad_sbom_files_rejected_clearly(tmp_path, content, msg):
    p = tmp_path / "bad.json"
    p.write_text(content)
    with pytest.raises(SbomError, match=msg):
        load_sbom(p)


def test_oversized_sbom_refused(tmp_path, monkeypatch):
    import cveprio.sbom as sbom
    monkeypatch.setattr(sbom, "MAX_SBOM_BYTES", 100)
    p = tmp_path / "big.json"
    p.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "x" * 200}]}))
    with pytest.raises(SbomError, match="limit"):
        load_sbom(p)


def test_inventory_references_sbom_relative_to_its_file():
    inv = attach_sboms(Inventory.model_validate_json((EX / "inventory-sbom.json").read_text()), EX)
    portal = next(a for a in inv.assets if a.id == "web-portal-01")
    assert portal.internet_facing is True and any(i.product == "log4j-core" for i in portal.software)
    assert any("SBOM" in n and "web-portal-01" in n for n in inv.input_notes)


def test_inventory_from_sboms_uses_supplied_context_only():
    inv = inventory_from_sboms([EX / "sbom" / "shipment-tracker.cdx.json"], criticality=None, internet_facing=None)
    a = inv.assets[0]
    assert a.id == "shipment-tracker" and a.criticality is None and a.internet_facing is None  # not invented


def test_osv_affirmation_makes_purl_item_affected():
    item = SoftwareItem(product="widget-lib", version="1.0.0", purl="pkg:npm/widget-lib@1.0.0")
    b = synthetic_bundle()
    assert assess(b, "a", item).status != ApplicabilityStatus.AFFECTED  # name alone is not enough
    r = assess(b, "a", item, osv_evidence_id="CVE.desc")
    assert r.status == ApplicabilityStatus.AFFECTED and r.matched_by == "OSV"


def test_cli_sbom_requires_discover_or_ids(capsys):
    from cveprio.cli import main
    assert main(["analyze", "--sbom", str(EX / "sbom" / "shipment-tracker.cdx.json")]) == 2
    assert "--discover" in capsys.readouterr().err


def test_examples_contain_no_local_paths():
    for dirpath, _, files in os.walk(EX):
        for f in files:
            text = open(os.path.join(dirpath, f), errors="ignore").read()
            assert "/Users/" not in text and "file:///" not in text and "C:\\\\Users" not in text, f
