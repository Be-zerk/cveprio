"""Record live API responses as offline demo fixtures (``cveprio capture-fixtures``).

Uses the same SafeFetcher as live mode (allowlist, limits, throttling). Writes a
``manifest.json`` mapping each URL to a file, HTTP status and retrieval time, so
fixture replays keep honest provenance. The KEV catalogue is trimmed to the
captured CVEs to keep the repository small; the trimmed file is marked and the
report warns that KEV *absence* was only verified at capture time.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from cveprio.net import FetchError, SafeFetcher
from cveprio.sources import (
    CVE_ORG_ID,
    CVE_ORG_RECORD,
    EPSS_API,
    KEV_FEED,
    NVD_CVE,
    REDHAT_CVE,
    UBUNTU_CVE,
    normalize_cve_id,
)


def _fname(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]+", "_", url.split("://", 1)[1])[:150] + ".json"


def capture(cve_ids: list[str], out_dir: Path, fetcher: SafeFetcher, nvd_api_key: str | None = None,
            distros: bool = True) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "responses").mkdir(exist_ok=True)
    manifest_path = out_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"responses": {}}
    ids = [normalize_cve_id(c) for c in cve_ids]

    def record(url: str, accept: tuple[int, ...] = (200, 404), headers: dict[str, str] | None = None) -> int:
        try:
            res = fetcher.get(url, accept_status=accept, headers=headers, max_bytes=16 * 1024 * 1024)
        except FetchError as err:
            print(f"  ! {url}: {err}")
            return -1
        name = "responses/" + _fname(url)
        body = res.body
        if "ubuntu.com/security" in url and res.status_code == 200:
            # Ubuntu's licence for this data is not stated; keep only the fields the tool uses.
            d = json.loads(body)
            keep = {"id": d.get("id"), "updated_at": d.get("updated_at"), "published": d.get("published"),
                    "packages": [{"name": p.get("name"), "statuses": [
                        {k: st.get(k) for k in ("release_codename", "status", "description")}
                        for st in p.get("statuses") or []]} for p in d.get("packages") or []],
                    "x_cveprio_note": "Trimmed to package status fields. Source: ubuntu.com/security (Canonical)."}
            body = json.dumps(keep, indent=1).encode()
        (out_dir / name).write_bytes(body)
        manifest["responses"][url] = {"file": name, "status": res.status_code,
                                      "retrieved_at": res.retrieved_at.isoformat()}
        print(f"  {res.status_code} {url}")
        return res.status_code

    for cid in ids:
        if record(CVE_ORG_RECORD.format(id=cid)) == 404:
            record(CVE_ORG_ID.format(id=cid))
        record(NVD_CVE.format(id=cid), accept=(200,), headers={"apiKey": nvd_api_key} if nvd_api_key else None)
        record(EPSS_API.format(ids=cid), accept=(200,))
        if distros:
            for url in (UBUNTU_CVE.format(id=cid), REDHAT_CVE.format(id=cid)):
                record(url)

    res = fetcher.get(KEV_FEED, max_bytes=16 * 1024 * 1024)
    full = json.loads(res.body)
    wanted = set(ids) | set(manifest.get("kev_cves", []))
    trimmed = {k: v for k, v in full.items() if k != "vulnerabilities"}
    trimmed["vulnerabilities"] = [v for v in full["vulnerabilities"] if v.get("cveID") in wanted]
    trimmed["x_cveprio_fixture_subset"] = True
    trimmed["x_cveprio_note"] = (f"Trimmed by cveprio capture: {len(trimmed['vulnerabilities'])} of "
                                 f"{len(full['vulnerabilities'])} entries kept (only the captured CVEs). "
                                 "CISA KEV is published under CC0 1.0.")
    (out_dir / "responses" / "kev_subset.json").write_text(json.dumps(trimmed, indent=1))
    manifest["responses"][KEV_FEED] = {"file": "responses/kev_subset.json", "status": 200,
                                       "retrieved_at": res.retrieved_at.isoformat()}
    manifest["kev_cves"] = sorted(wanted)
    manifest["captured_at"] = datetime.now(UTC).isoformat()
    manifest["notice"] = ("OFFLINE DEMO FIXTURES: real API responses recorded at the times shown. They go stale; "
                          "use live mode for current data. This product uses the NVD API but is not endorsed "
                          "or certified by the NVD.")
    manifest_path.write_text(json.dumps(manifest, indent=1, sort_keys=True))
    return manifest_path
