"""Is a deployed software item affected by a CVE?

Each matching source statement (CNA/ADP ``affected`` entry, NVD CPE match) yields
a verdict: affected / not_affected / ambiguous. They are combined conservatively:

* product identity must match exactly (normalised vendor+product, package name,
  or CPE vendor:product). Similar names only produce a *review* candidate;
* any ambiguous statement blocks a ``not_affected`` conclusion;
* definite affected + definite not-affected from different sources -> review;
* no structured data at all -> review (not "unaffected").
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from functools import cmp_to_key

from cveprio.llm.versions import Reading
from cveprio.models import (
    AffectedEntry,
    ApplicabilityResult,
    ApplicabilityStatus,
    CpeMatch,
    EvidenceBundle,
    RecordState,
    SoftwareItem,
    VersionSpec,
)
from cveprio.versions import compare, compare_deb, compare_rpm, looks_like_distro_version, parse_simple_constraint

AFFECTED, NOT_AFFECTED, AMBIGUOUS = "affected", "not_affected", "ambiguous"
FUZZY_THRESHOLD = 0.75


def norm(s: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _cpe_parts(cpe: str | None) -> tuple[str, str, str] | None:
    if not cpe:
        return None
    parts = cpe.split(":")
    if cpe.startswith("cpe:2.3:") and len(parts) >= 6:
        return parts[3], parts[4], parts[5]
    if cpe.startswith("cpe:/") and len(parts) >= 4:
        return parts[2], parts[3], parts[4] if len(parts) > 4 else "*"
    return None


@dataclass
class Verdict:
    verdict: str
    source: str
    reason: str
    evidence_id: str
    fixed_hint: str | None = None
    ai: bool = False  # depends on an AI reading of a free-text version statement


@dataclass
class _Acc:
    verdicts: list[Verdict] = field(default_factory=list)
    fuzzy: list[str] = field(default_factory=list)
    fuzzy_ids: list[str] = field(default_factory=list)


# ------------------------------------------------------------------- CVE JSON 5


def _identity_match(item: SoftwareItem, entry: AffectedEntry) -> tuple[bool, bool, str]:
    """Returns (exact, fuzzy, how)."""
    inv_names = {norm(item.product), norm(item.package_name)} - {""}
    entry_names = {norm(entry.product), norm(entry.package_name)} - {"", "n a"}
    if item.cpe and entry.cpes:
        ip = _cpe_parts(item.cpe)
        for c in entry.cpes:
            ep = _cpe_parts(c)
            if ip and ep and ip[0] == ep[0] and ip[1] == ep[1]:
                return True, False, f"CPE {ep[0]}:{ep[1]}"
    exact = inv_names & entry_names
    if exact and entry.product and norm(entry.product) not in inv_names and entry.vendor:
        # Matched only via package name inside a vendor product (e.g. Red Hat's "openssh" package in
        # "Red Hat Enterprise Linux 9"): that statement is about the vendor's build, so it applies only
        # when the inventory says the software comes from that vendor.
        if not item.vendor or norm(item.vendor) != norm(entry.vendor):
            return False, False, ""
    if exact:
        if item.vendor and entry.vendor and norm(entry.vendor) not in {"n a", ""} \
                and norm(item.vendor) != norm(entry.vendor):
            return False, True, f"name '{next(iter(exact))}' matches but vendor differs ({entry.vendor})"
        return True, False, f"name '{next(iter(exact))}'"
    for a in inv_names:
        for b in entry_names:
            if SequenceMatcher(None, a, b).ratio() >= FUZZY_THRESHOLD or (len(a) > 3 and a in b) or (len(b) > 3 and b in a):
                return False, True, f"similar name: '{a}' vs '{b}'"
    return False, False, ""


def _spec_verdict(version: str, spec: VersionSpec) -> tuple[str | None, str, str | None]:
    """Evaluate one CVE5 version statement. Returns (verdict|None=not covered, reason, fixed_hint)."""
    scheme = spec.version_type
    upper, inclusive = (spec.less_than, False) if spec.less_than else (spec.less_than_or_equal, True)
    if upper:
        start = spec.version or "0"
        if upper != "*" and compare(upper, upper, scheme) is None:
            return AMBIGUOUS, f"upper bound '{upper}' is not a comparable version", None
        if start not in {"0", "*"} and upper != "*" and compare(start, upper, scheme) == 0 and not inclusive:
            return AMBIGUOUS, f"malformed range in source: [{start}, {upper}) is empty", None
        lo = 1 if start in {"0", "*"} else compare(version, start, scheme)
        hi = -1 if upper == "*" else compare(version, upper, scheme)
        if lo is None or hi is None:
            return AMBIGUOUS, f"cannot compare '{version}' with range {start}..{upper} ({scheme or 'unspecified'})", None
        in_range = lo >= 0 and (hi < 0 or (inclusive and hi == 0))
        if not in_range:
            return None, f"outside {start}..{'≤' if inclusive else '<'}{upper}", None
        status = spec.status or "affected"
        points = [ch for ch in spec.changes if ch.get("at")]
        if any(compare(version, str(ch["at"]), scheme) is None for ch in points):
            return AMBIGUOUS, "cannot compare with a change point in the source range", None
        points.sort(key=cmp_to_key(lambda x, y: compare(str(x["at"]), str(y["at"]), scheme) or 0))
        for ch in points:
            if (compare(version, str(ch["at"]), scheme) or 0) >= 0:
                status = ch.get("status", status)
        fixed = None if inclusive or upper == "*" else upper
        verdict = AFFECTED if status == "affected" else NOT_AFFECTED if status == "unaffected" else AMBIGUOUS
        return verdict, f"in range {start}..{'≤' if inclusive else '<'}{upper} → {status}", fixed
    if spec.version:
        simple = parse_simple_constraint(spec.version)
        if simple:
            op, bound = simple
            c = compare(version, bound, scheme)
            if c is None:
                return AMBIGUOUS, f"cannot compare '{version}' with '{spec.version}'", None
            hit = c < 0 or (op == "<=" and c == 0)
            if not hit:
                return None, f"outside free-text constraint '{spec.version}'", None
            return (AFFECTED if (spec.status or "affected") == "affected" else NOT_AFFECTED,
                    f"matches free-text constraint '{spec.version}' (parsed as {op} {bound})", None)
        c = compare(version, spec.version, scheme)
        if c is None:
            return AMBIGUOUS, f"version statement '{spec.version[:80]}' is not machine-comparable", None
        if c != 0:
            return None, f"≠ {spec.version}", None
        status = spec.status or "affected"
        return (AFFECTED if status == "affected" else NOT_AFFECTED if status == "unaffected" else AMBIGUOUS,
                f"exact version {spec.version} → {status}", None)
    return AMBIGUOUS, "version statement has no version", None


def _eval_entry(item: SoftwareItem, entry: AffectedEntry, readings: Mapping[tuple[str, str], Reading] | None = None,
                ) -> Verdict:
    verdicts = []
    ai_notes: list[str] = []
    for s in entry.versions:
        v = _spec_verdict(item.version, s)
        reading = (readings or {}).get((entry.evidence_id, (s.version or "").strip()[:500]))
        if v[0] == AMBIGUOUS and reading:
            verdict, why = reading.evaluate(item.version, s.version_type)
            v = (verdict, why, None)
            ai_notes.append(why)
        verdicts.append(v)
    covered = [(v, r, f) for v, r, f in verdicts if v is not None]
    label = f"{entry.provider} '{entry.product or entry.package_name}'"
    out = _combine_entry(entry, covered, label)
    if ai_notes:
        out.ai = True
        if not any(n in out.reason for n in ai_notes):
            out.reason = f"{'; '.join(ai_notes)}; so: {out.reason}"
    return out


def _combine_entry(entry: AffectedEntry, covered: list[tuple[str, str, str | None]], label: str) -> Verdict:
    if any(v == AFFECTED for v, _, _ in covered):
        _, r, f = next(x for x in covered if x[0] == AFFECTED)
        return Verdict(AFFECTED, label, r, entry.evidence_id, f)
    if any(v == AMBIGUOUS for v, _, _ in covered):
        _, r, _ = next(x for x in covered if x[0] == AMBIGUOUS)
        return Verdict(AMBIGUOUS, label, r, entry.evidence_id)
    if any(v == NOT_AFFECTED for v, _, _ in covered):
        _, r, _ = next(x for x in covered if x[0] == NOT_AFFECTED)
        return Verdict(NOT_AFFECTED, label, r, entry.evidence_id)
    default = (entry.default_status or "").lower()
    if default == "unaffected":
        return Verdict(NOT_AFFECTED, label, "version not listed; source default status is 'unaffected'",
                       entry.evidence_id)
    if default == "affected":
        return Verdict(AFFECTED, label, "version not listed; source default status is 'affected'", entry.evidence_id)
    return Verdict(AMBIGUOUS, label, "version not covered by any statement and default status is unspecified",
                   entry.evidence_id)


# ------------------------------------------------------------------------- NVD CPE


def _cpe_identity(item: SoftwareItem) -> tuple[str, str] | None:
    parts = _cpe_parts(item.cpe)
    if parts:
        return parts[0], parts[1]
    if item.vendor:
        return norm(item.vendor).replace(" ", "_"), norm(item.product).replace(" ", "_")
    return None


def _eval_cpe(item: SoftwareItem, m: CpeMatch) -> Verdict | None:
    v = item.version
    label = f"NVD {m.vendor}:{m.product}"
    bounds = [
        (m.version_start_including, lambda c: c >= 0, "≥"),
        (m.version_start_excluding, lambda c: c > 0, ">"),
        (m.version_end_including, lambda c: c <= 0, "≤"),
        (m.version_end_excluding, lambda c: c < 0, "<"),
    ]
    if m.version not in {"*", "-"}:
        c = compare(v, m.version.replace("\\", ""))
        if c is None:
            return Verdict(AMBIGUOUS, label, f"cannot compare '{v}' with CPE version '{m.version}'", m.evidence_id)
        if c != 0:
            return None
        reason = f"exact CPE version {m.version}"
    elif any(b for b, _, _ in bounds):
        desc = []
        for bound, ok, sym in bounds:
            if not bound:
                continue
            c = compare(v, bound)
            if c is None:
                return Verdict(AMBIGUOUS, label, f"cannot compare '{v}' with bound {sym}{bound}", m.evidence_id)
            if not ok(c):
                return None
            desc.append(f"{sym}{bound}")
        reason = "in range " + " ".join(desc)
    else:
        return Verdict(AMBIGUOUS, label, "CPE matches all versions ('*') without bounds", m.evidence_id)
    if m.in_and_node:
        return Verdict(AMBIGUOUS, label, reason + "; NVD applies this only in combination with "
                       + (", ".join(m.and_with) or "another platform") + " (AND configuration) — confirm that "
                       "platform condition for this deployment", m.evidence_id)
    return Verdict(AFFECTED, label, reason, m.evidence_id, m.version_end_excluding)


# ----------------------------------------------------------------- distribution data

UBUNTU_RELEASES = {"14.04": "trusty", "16.04": "xenial", "18.04": "bionic", "20.04": "focal", "22.04": "jammy",
                   "23.10": "mantic", "24.04": "noble", "24.10": "oracular", "25.04": "plucky"}
_BINARY_SUFFIXES = ("-server", "-client", "-sftp-server", "-bin", "-common", "-utils", "-tools", "-dev", "-data")
UBUNTU_AFFECTED = {"needed", "deferred", "pending", "active", "ignored"}


def _distro(item: SoftwareItem) -> tuple[str, str] | None:
    """('ubuntu', 'noble') / ('rhel', '9') from item.distro or a purl ?distro= qualifier."""
    raw = item.distro
    if not raw and item.purl and "distro=" in item.purl:
        raw = item.purl.split("distro=", 1)[1].split("&")[0].replace("-", ":", 1)
    if not raw or ":" not in raw:
        return None
    family, _, release = raw.lower().partition(":")
    if family == "ubuntu":
        return "ubuntu", UBUNTU_RELEASES.get(release, release)
    if family in ("rhel", "redhat", "red hat enterprise linux"):
        return "rhel", release.split(".")[0]
    return None


def _source_names(item: SoftwareItem) -> list[str]:
    names = [n.lower() for n in (item.source_package, item.package_name, item.product) if n]
    for n in list(names):
        for suf in _BINARY_SUFFIXES:
            if n.endswith(suf):
                names.append(n[: -len(suf)])
    return list(dict.fromkeys(names))


def _installed_pkg_version(item: SoftwareItem) -> str:
    v = item.version
    if item.purl and "@" in item.purl:
        v = item.purl.split("@", 1)[1].split("?")[0]
    return v


def _distro_verdict(bundle: EvidenceBundle, item: SoftwareItem) -> Verdict | None:
    d = _distro(item)
    if not d:
        return None
    family, release = d
    names = _source_names(item)
    installed = _installed_pkg_version(item)
    if family == "ubuntu":
        ev = bundle.get("UBUNTU")
        if not ev:
            return None
        for pkg in ev.fields.get("packages") or []:
            if str(pkg.get("name", "")).lower() not in names:
                continue
            st = next((s for s in pkg.get("statuses") or [] if s.get("release") == release), None)
            if not st:
                return Verdict(AMBIGUOUS, f"Ubuntu ({release})", f"Ubuntu lists no status for release {release}",
                               ev.id)
            status, desc = st.get("status"), str(st.get("description") or "")
            if status in ("not-affected", "DNE"):
                why = "does not exist in this release" if status == "DNE" else "not affected"
                return Verdict(NOT_AFFECTED, f"Ubuntu ({release})", f"Ubuntu marks {pkg['name']} as {why}"
                               + (f" ({desc})" if desc else ""), ev.id)
            if status == "released" and desc:
                c = compare_deb(installed, desc)
                if c is None:
                    return Verdict(AMBIGUOUS, f"Ubuntu ({release})", f"could not compare '{installed}' with Ubuntu's "
                                   f"fixed version {desc}", ev.id)
                if c >= 0:
                    return Verdict(NOT_AFFECTED, f"Ubuntu ({release})", f"Ubuntu fixed {pkg['name']} in {desc}; the "
                                   f"installed {installed} is that version or newer", ev.id)
                return Verdict(AFFECTED, f"Ubuntu ({release})", f"Ubuntu fixed {pkg['name']} in {desc}; the "
                               f"installed {installed} is older", ev.id, desc)
            if status in UBUNTU_AFFECTED:
                return Verdict(AFFECTED, f"Ubuntu ({release})", f"Ubuntu status '{status}': no fix is available for "
                               f"this release yet" if status != "ignored" else "Ubuntu will not fix this release",
                               ev.id)
            return Verdict(AMBIGUOUS, f"Ubuntu ({release})", f"Ubuntu status '{status}' (not yet triaged)", ev.id)
        return None
    ev = bundle.get("REDHAT")
    if not ev:
        return None
    product = f"red hat enterprise linux {release}"
    for a in ev.fields.get("affected_release") or []:
        if str(a.get("product", "")).lower() != product:
            continue
        m = re.match(r"^(?P<name>.+)-(?P<evr>\d+:.+)$", str(a.get("package") or ""))
        if not m or m.group("name").lower() not in names:
            continue
        fixed = m.group("evr")
        c = compare_rpm(installed, fixed)
        if c is None:
            return Verdict(AMBIGUOUS, f"Red Hat (RHEL {release})", f"could not compare '{installed}' with Red Hat's "
                           f"fixed version {fixed}", ev.id)
        if c >= 0:
            return Verdict(NOT_AFFECTED, f"Red Hat (RHEL {release})", f"Red Hat fixed {m.group('name')} in {fixed}; "
                           f"the installed {installed} is that version or newer", ev.id)
        return Verdict(AFFECTED, f"Red Hat (RHEL {release})", f"Red Hat fixed {m.group('name')} in {fixed}; the "
                       f"installed {installed} is older", ev.id, fixed)
    for p in ev.fields.get("package_state") or []:
        if str(p.get("product", "")).lower() != product or str(p.get("package", "")).lower() not in names:
            continue
        state = str(p.get("fix_state", ""))
        if state == "Not affected":
            return Verdict(NOT_AFFECTED, f"Red Hat (RHEL {release})", f"Red Hat marks {p['package']} as not affected",
                           ev.id)
        if state in ("Affected", "Fix deferred", "Will not fix", "Out of support scope"):
            return Verdict(AFFECTED, f"Red Hat (RHEL {release})", f"Red Hat status '{state}': no fix shipped", ev.id)
        return Verdict(AMBIGUOUS, f"Red Hat (RHEL {release})", f"Red Hat status '{state}'", ev.id)
    return None


# --------------------------------------------------------------------------- main


def assess(bundle: EvidenceBundle, asset_id: str, item: SoftwareItem,
           osv_evidence_id: str | None = None,
           readings: Mapping[tuple[str, str], Reading] | None = None) -> ApplicabilityResult:
    def result(status: ApplicabilityStatus, reasons: list[str], ids: list[str], by: str | None = None,
               fixed: str | None = None, ai: bool = False) -> ApplicabilityResult:
        return ApplicabilityResult(asset_id=asset_id, software=item, status=status, matched_by=by,
                                   reasons=reasons, evidence_ids=sorted(set(ids)), fixed_version_hint=fixed,
                                   resolved_with_ai=ai)

    if bundle.record_state != RecordState.PUBLISHED:
        return result(ApplicabilityStatus.NO_PRODUCT_MATCH, [f"record is {bundle.record_state}"], [])

    # A distribution build is judged by that distribution's own advisory: vendors backport fixes without changing
    # the upstream version, so upstream ranges cannot decide it. Fall back to upstream data only if there is none.
    dv = _distro_verdict(bundle, item)
    if dv and dv.verdict != AMBIGUOUS:
        status = ApplicabilityStatus.AFFECTED if dv.verdict == AFFECTED else ApplicabilityStatus.NOT_AFFECTED
        return result(status, [f"[{dv.verdict}] {dv.source}: {dv.reason}", "Distribution builds are judged by the "
                               "distribution's own advisory, not upstream version ranges."],
                      [dv.evidence_id], dv.source, dv.fixed_hint)

    acc = _Acc()
    for entry in bundle.affected:
        exact, fuzzy, how = _identity_match(item, entry)
        if exact:
            v = _eval_entry(item, entry, readings)
            v.reason = f"{how}: {v.reason}"
            acc.verdicts.append(v)
        elif fuzzy:
            acc.fuzzy.append(f"{entry.provider}: {how}")
            acc.fuzzy_ids.append(entry.evidence_id)

    if osv_evidence_id:
        # OSV was asked about this exact package URL + version and listed this CVE for it.
        acc.verdicts.append(Verdict(AFFECTED, "OSV", f"OSV lists {item.purl} as affected", osv_evidence_id))
    ident = _cpe_identity(item)
    if ident:
        cpe_hits = [m for m in bundle.cpe_matches if (m.vendor, m.product) == ident]
        verdicts = [v for v in (_eval_cpe(item, m) for m in cpe_hits) if v]
        if cpe_hits and not verdicts:
            acc.verdicts.append(Verdict(NOT_AFFECTED, f"NVD {ident[0]}:{ident[1]}",
                                        f"version {item.version} outside all {len(cpe_hits)} NVD ranges",
                                        cpe_hits[0].evidence_id))
        affected = [v for v in verdicts if v.verdict == AFFECTED]
        acc.verdicts.extend(affected[:1] or verdicts[:1])
        if not cpe_hits:
            for m in bundle.cpe_matches:
                if m.product == ident[1] or SequenceMatcher(None, m.product, ident[1]).ratio() >= 0.85:
                    acc.fuzzy.append(f"NVD CPE {m.vendor}:{m.product} resembles {ident[0]}:{ident[1]}")
                    acc.fuzzy_ids.append(m.evidence_id)
                    break

    ids = [v.evidence_id for v in acc.verdicts]
    reasons = [f"[{v.verdict}] {v.source}: {v.reason}" for v in acc.verdicts]
    distro = looks_like_distro_version(item.version)
    if distro:
        reasons.append(f"'{item.version}' looks like a distribution package version; vendors often backport "
                       "fixes without changing the upstream version — check the distribution's advisory.")

    if not acc.verdicts:
        if acc.fuzzy:
            return result(ApplicabilityStatus.NEEDS_REVIEW,
                          ["No exact product match; similar product names found (similarity does not establish "
                           "that this deployment is affected):", *acc.fuzzy], acc.fuzzy_ids)
        if not bundle.affected and not bundle.cpe_matches:
            return result(ApplicabilityStatus.NEEDS_REVIEW,
                          ["Sources provide no structured affected-product data; manual check required."], [])
        return result(ApplicabilityStatus.NO_PRODUCT_MATCH,
                      ["Product does not appear in the CVE's affected-product data."], [])

    kinds = {v.verdict for v in acc.verdicts}
    fixed = next((v.fixed_hint for v in acc.verdicts if v.fixed_hint), None)
    if AFFECTED in kinds and NOT_AFFECTED in kinds:
        return result(ApplicabilityStatus.NEEDS_REVIEW, ["Sources disagree for this version:", *reasons], ids)
    if distro and kinds != {NOT_AFFECTED}:
        return result(ApplicabilityStatus.NEEDS_REVIEW, reasons, ids)
    if AFFECTED in kinds:
        firm = [v for v in acc.verdicts if v.verdict == AFFECTED and not v.ai]
        hit = (firm or [v for v in acc.verdicts if v.verdict == AFFECTED])[0]
        return result(ApplicabilityStatus.AFFECTED, reasons, ids, hit.source, fixed, ai=not firm)
    if AMBIGUOUS in kinds:
        return result(ApplicabilityStatus.NEEDS_REVIEW, reasons, ids)
    if all(v.ai for v in acc.verdicts):
        # An AI reading alone never clears a system: a structured source must independently agree.
        return result(ApplicabilityStatus.NEEDS_REVIEW, [*reasons, "The AI reading suggests this version is not "
                      "affected, but no structured source confirms it, so it is not used to clear the system."], ids)
    return result(ApplicabilityStatus.NOT_AFFECTED, reasons, ids, acc.verdicts[0].source,
                  ai=any(v.ai for v in acc.verdicts))
