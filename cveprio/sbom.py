"""Read a software bill of materials (SBOM) into inventory software items.

Supported (JSON only):
* CycloneDX 1.x — ``components[]`` (nested components included): name, version, group,
  purl, cpe, supplier/publisher. Checked against a file produced by cyclonedx-py 7.5.
* SPDX 2.x — ``packages[]``: name, versionInfo, supplier, externalRefs (purl, cpe23Type).
  Field names checked against the official SPDX 2.3 JSON schema.

The SBOM is untrusted input: size and component counts are capped, strings are trimmed,
nothing in it is fetched, and every component that cannot be used is reported with a
reason instead of being dropped silently.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cveprio.models import Asset, Inventory, SoftwareItem

MAX_SBOM_BYTES = 25 * 1024 * 1024
MAX_COMPONENTS = 5000
MAX_STR = 300
SKIP_TYPES = {"file", "data", "machine-learning-model", "cryptographic-asset"}


class SbomError(ValueError):
    pass


@dataclass
class SbomResult:
    path: str
    format: str  # "CycloneDX 1.6", "SPDX-2.3"
    subject: str | None  # what the SBOM describes, if stated
    items: list[SoftwareItem]
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (component, reason)

    def describe(self) -> str:
        s = f"{len(self.items)} components read from {Path(self.path).name} ({self.format})"
        if self.skipped:
            s += f"; {len(self.skipped)} skipped (e.g. {self.skipped[0][0]}: {self.skipped[0][1]})"
        return s


def _s(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:MAX_STR] if text else None


def load_sbom(path: Path) -> SbomResult:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SbomError(f"cannot read SBOM {path}: {exc}") from exc
    if size > MAX_SBOM_BYTES:
        raise SbomError(f"SBOM {path.name} is {size} bytes; limit is {MAX_SBOM_BYTES}")
    raw = path.read_text(encoding="utf-8", errors="replace")
    if raw.lstrip().startswith("<"):
        raise SbomError(f"{path.name} looks like XML; only JSON SBOMs (CycloneDX or SPDX 2.x) are supported")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SbomError(f"{path.name} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise SbomError(f"{path.name}: expected a JSON object")
    if doc.get("bomFormat") == "CycloneDX":
        return _cyclonedx(doc, str(path))
    if str(doc.get("spdxVersion", "")).startswith("SPDX-2"):
        return _spdx(doc, str(path))
    if "@context" in doc and "spdx" in json.dumps(doc.get("@context", "")).lower():
        raise SbomError(f"{path.name} looks like SPDX 3 (JSON-LD), which is not supported yet; export SPDX 2.3 JSON")
    raise SbomError(f"{path.name}: not a recognised SBOM (need CycloneDX JSON or SPDX 2.x JSON)")


def _finish(result: SbomResult) -> SbomResult:
    seen: set[tuple[str, str, str | None]] = set()
    unique = []
    for it in result.items:
        key = (it.product.lower(), it.version, it.purl)
        if key not in seen:
            seen.add(key)
            unique.append(it)
    result.items = unique
    if len(result.items) > MAX_COMPONENTS:
        extra = len(result.items) - MAX_COMPONENTS
        result.skipped.append((f"{extra} components", f"over the {MAX_COMPONENTS}-component limit"))
        result.items = result.items[:MAX_COMPONENTS]
    return result


def _cyclonedx(doc: dict[str, Any], path: str) -> SbomResult:
    meta = doc.get("metadata") or {}
    subject = _s((meta.get("component") or {}).get("name"))
    res = SbomResult(path=path, format=f"CycloneDX {doc.get('specVersion', '?')}", subject=subject, items=[])
    stack = list(doc.get("components") or [])
    visited = 0
    while stack:
        c = stack.pop(0)
        visited += 1
        if visited > MAX_COMPONENTS * 2 or not isinstance(c, dict):
            break
        stack.extend(c.get("components") or [])  # nested components
        name, version = _s(c.get("name")), _s(c.get("version"))
        label = f"{name or '?'} {version or ''}".strip()
        if (c.get("type") or "library") in SKIP_TYPES:
            res.skipped.append((label, f"type '{c.get('type')}' is not software"))
            continue
        if not name or not version:
            res.skipped.append((label, "no version" if name else "no name"))
            continue
        supplier = c.get("supplier") or {}
        vendor = _s(supplier.get("name") if isinstance(supplier, dict) else None) or _s(c.get("publisher"))
        res.items.append(SoftwareItem(
            vendor=vendor, product=name, version=version, package_name=name,
            purl=_s(c.get("purl")), cpe=_s(c.get("cpe")),
            notes=f"from SBOM{(' (group ' + str(c.get('group')) + ')') if c.get('group') else ''}"))
    return _finish(res)


def _spdx(doc: dict[str, Any], path: str) -> SbomResult:
    res = SbomResult(path=path, format=str(doc.get("spdxVersion")), subject=_s(doc.get("name")), items=[])
    for p in doc.get("packages") or []:
        if not isinstance(p, dict):
            continue
        name, version = _s(p.get("name")), _s(p.get("versionInfo"))
        if version in ("NOASSERTION", "NONE"):
            version = None
        label = f"{name or '?'} {version or ''}".strip()
        if not name or not version:
            res.skipped.append((label, "no version" if name else "no name"))
            continue
        purl = cpe = None
        for ref in p.get("externalRefs") or []:
            rtype, loc = str(ref.get("referenceType", "")), _s(ref.get("referenceLocator"))
            if rtype == "purl" and not purl:
                purl = loc
            elif rtype == "cpe23Type" and not cpe:
                cpe = loc
        supplier = _s(p.get("supplier"))
        vendor = None
        if supplier and supplier != "NOASSERTION":
            vendor = supplier.split(":", 1)[-1].split("(")[0].strip() or None
        res.items.append(SoftwareItem(vendor=vendor, product=name, version=version, package_name=name,
                                      purl=purl, cpe=cpe, notes="from SBOM"))
    return _finish(res)


def attach_sboms(inventory: Inventory, base_dir: Path) -> Inventory:
    """Load each asset's ``sbom`` file (path relative to the inventory) and add its components."""
    for asset in inventory.assets:
        if not asset.sbom:
            continue
        res = load_sbom((base_dir / asset.sbom).resolve())
        asset.software.extend(res.items)
        inventory.input_notes.append(f"{asset.id}: software list from SBOM — {res.describe()}.")
    return inventory


def inventory_from_sboms(paths: list[Path], *, criticality: str | None, internet_facing: bool | None) -> Inventory:
    """One asset per SBOM file; business context comes from the command line (None = not supplied)."""
    assets, notes = [], []
    for p in paths:
        res = load_sbom(p)
        asset_id = (res.subject or p.stem.split(".")[0]).replace(" ", "-")[:60]
        assets.append(Asset(id=asset_id, name=res.subject or p.name, software=res.items,
                            criticality=criticality, internet_facing=internet_facing))  # type: ignore[arg-type]
        notes.append(f"{asset_id}: software list from SBOM — {res.describe()}.")
    return Inventory(assets=assets, input_notes=notes)
