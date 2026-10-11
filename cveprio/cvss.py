"""Display helpers: CVSS vectors, score-source names and CWE weakness names in plain words.

Display only — the rules use base scores and IDs. CWE names come from MITRE's CWE list
(see cveprio/data/cwe_names.json for source, copyright and licence).
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path

METRICS: dict[str, tuple[str, dict[str, str]]] = {
    "AV": ("Attack from", {"N": "the network (remotely)", "A": "the same local network", "L": "the machine itself (local access)",
                           "P": "physical access to the device"}),
    "AC": ("Attack complexity", {"L": "low — no special conditions", "H": "high — needs special conditions or timing"}),
    "AT": ("Attack requirements", {"N": "none", "P": "some deployment conditions must be present"}),
    "PR": ("Login / privileges needed", {"N": "none", "L": "a normal user account", "H": "an administrator account"}),
    "UI": ("A user must do something", {"N": "no", "R": "yes (e.g. open a file or click a link)", "P": "yes, passively",
                                        "A": "yes, actively"}),
    "S": ("Impact spreads beyond the component", {"U": "no", "C": "yes"}),
    "C": ("Impact on confidentiality (data theft)", {"H": "high", "L": "low", "N": "none"}),
    "I": ("Impact on integrity (data tampering)", {"H": "high", "L": "low", "N": "none"}),
    "A": ("Impact on availability (outage)", {"H": "high", "L": "low", "N": "none"}),
    "VC": ("Confidentiality impact on the vulnerable system", {"H": "high", "L": "low", "N": "none"}),
    "VI": ("Integrity impact on the vulnerable system", {"H": "high", "L": "low", "N": "none"}),
    "VA": ("Availability impact on the vulnerable system", {"H": "high", "L": "low", "N": "none"}),
    "SC": ("Confidentiality impact on other systems", {"H": "high", "L": "low", "N": "none"}),
    "SI": ("Integrity impact on other systems", {"H": "high", "L": "low", "N": "none"}),
    "SA": ("Availability impact on other systems", {"H": "high", "L": "low", "N": "none"}),
}
V2: dict[str, tuple[str, dict[str, str]]] = {
    "AV": METRICS["AV"],
    "AC": ("Attack complexity", {"L": "low", "M": "medium", "H": "high"}),
    "Au": ("Authentication needed", {"N": "none", "S": "once", "M": "multiple times"}),
    "C": ("Impact on confidentiality (data theft)", {"C": "complete", "P": "partial", "N": "none"}),
    "I": ("Impact on integrity (data tampering)", {"C": "complete", "P": "partial", "N": "none"}),
    "A": ("Impact on availability (outage)", {"C": "complete", "P": "partial", "N": "none"}),
}


def explain_vector(vector: str | None) -> list[tuple[str, str]]:
    """'CVSS:3.1/AV:N/AC:L/...' -> [("Attack from", "the network (remotely)"), ...]. Unknown parts are kept raw."""
    if not vector:
        return []
    parts = vector.split("/")
    table = METRICS if parts[0].startswith("CVSS:") else V2
    out = []
    for part in parts[1:] if parts[0].startswith("CVSS:") else parts:
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        if key in table:
            name, values = table[key]
            out.append((name, values.get(val, val)))
    return out


def source_name(provider: str) -> str:
    """Readable name for a CVSS score provider (raw IDs stay in the evidence table)."""
    if provider in ("nvd@nist.gov",):
        return "NVD"
    if provider.startswith("ADP:CISA"):
        return "CISA"
    if provider.endswith(" (copy in NVD)"):
        inner = provider.removesuffix(" (copy in NVD)")
        return ("CISA" if inner.startswith("CISA") else inner) + " (copy in NVD)"
    if provider.startswith("CNA:"):
        return f"{provider[4:]}, which published the CVE"
    if provider.startswith("ADP:"):
        return provider[4:]
    if "@" in provider:
        return provider.split("@")[1]
    return "another scoring organisation" if len(provider) > 30 else provider


@cache
def _cwe_names() -> dict[str, str]:
    data = json.loads((Path(__file__).parent / "data" / "cwe_names.json").read_text(encoding="utf-8"))
    return dict(data["names"])


def cwe_name(cwe_id: str) -> str | None:
    """Official MITRE name, e.g. 'CWE-400' -> 'Uncontrolled Resource Consumption'."""
    return _cwe_names().get(cwe_id)


def cwe_short(cwe_id: str, limit: int = 45) -> str:
    """Short readable label: the common name in quotes if MITRE gives one ('Path Traversal'), else the name."""
    name = cwe_name(cwe_id)
    if not name:
        return cwe_id
    common = re.findall(r"\('([^']+)'\)", name)
    if common:
        return common[-1]
    return name if len(name) <= limit else name[:limit].rsplit(" ", 1)[0] + "…"
