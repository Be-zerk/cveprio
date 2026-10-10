"""AC8–AC9: product identity and version applicability."""

from __future__ import annotations

import pytest

from cveprio.applicability import assess
from cveprio.models import ApplicabilityStatus as S
from cveprio.models import SoftwareItem
from cveprio.versions import compare, looks_like_distro_version
from tests.conftest import cve5_record, nvd_response, synthetic_bundle

# ------------------------------------------------------------------ versions


@pytest.mark.parametrize("a,b,expected", [
    ("1.2.10", "1.2.9", 1), ("2.0", "2.0.0", 0), ("9.6p1", "9.7p1", -1), ("9.7p1", "9.7", 1),
    ("2.0-beta9", "2.0", -1), ("2.0-rc1", "2.0-beta9", 1), ("1.1.1w", "1.1.1a", 1), ("5.3.17", "5.3.18", -1),
])
def test_compare_supported(a, b, expected):
    assert compare(a, b) == expected


@pytest.mark.parametrize("a,b", [
    ("1:9.6p1-3ubuntu13.4", "9.7p1"),   # Debian/Ubuntu epoch + revision
    ("0:8.7p1-38.el9_4.1", "8.7p1"),    # RPM
    ("2.x", "2.15.0"),                  # wildcard text
    ("latest", "1.0"),
    ("log4j-core*", "2.0"),
])
def test_compare_refuses_ambiguous(a, b):
    assert compare(a, b) is None


def test_rpm_scheme_not_compared():
    assert compare("8.7p1", "8.7p1", "rpm") is None
    assert looks_like_distro_version("1:9.6p1-3ubuntu13.4")


# --------------------------------------------------------- real-data matching


def item(**kw):
    return SoftwareItem(**kw)


def test_log4j_affected_via_nvd_cpe(real_bundle):
    r = assess(real_bundle("CVE-2021-44228"), "a", item(vendor="Apache", product="log4j-core", version="2.14.1",
                                                        cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"))
    assert r.status == S.AFFECTED and r.fixed_version_hint == "2.15.0"
    assert "NVD.cpe" in r.evidence_ids


def test_log4j_fixed_version_not_affected(real_bundle):
    r = assess(real_bundle("CVE-2021-44228"), "a", item(vendor="Apache", product="log4j-core", version="2.17.1",
                                                        cpe="cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*"))
    assert r.status == S.NOT_AFFECTED


def test_similar_name_without_identity_needs_review(real_bundle):
    r = assess(real_bundle("CVE-2021-44228"), "a", item(product="Log4j", version="2.x (bundled)"))
    assert r.status == S.NEEDS_REVIEW
    assert any("similar" in x for x in r.reasons)


def test_distro_package_version_needs_review(real_bundle):
    r = assess(real_bundle("CVE-2024-6387"), "a", item(product="OpenSSH", package_name="openssh-server",
                                                       version="1:9.6p1-3ubuntu13.4"))
    assert r.status == S.NEEDS_REVIEW
    assert any("backport" in x for x in r.reasons)


def test_upstream_openssh_affected_and_vendor_scoped_entries_ignored(real_bundle):
    r = assess(real_bundle("CVE-2024-6387"), "a", item(vendor="OpenBSD", product="OpenSSH", version="9.6p1",
                                                       cpe="cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"))
    assert r.status == S.AFFECTED
    assert not any("Red Hat" in x for x in r.reasons)  # RHEL-package statements don't apply to upstream builds


def test_platform_conditional_cpe_needs_review(real_bundle):
    # Spring4Shell: NVD config is spring_framework AND oracle:jdk -> platform condition must be confirmed
    r = assess(real_bundle("CVE-2022-22965"), "a", item(vendor="VMware", product="Spring Framework", version="5.3.17",
                                                        cpe="cpe:2.3:a:vmware:spring_framework:5.3.17:*:*:*:*:*:*:*"))
    assert r.status == S.NEEDS_REVIEW
    assert any("oracle:jdk" in x for x in r.reasons)


def test_not_affected_version_with_two_agreeing_sources(real_bundle):
    r = assess(real_bundle("CVE-2024-3094"), "a", item(vendor="Tukaani", product="xz", version="5.4.6",
                                                       cpe="cpe:2.3:a:tukaani:xz:5.4.6:*:*:*:*:*:*:*"))
    assert r.status == S.NOT_AFFECTED


def test_affected_backdoored_xz(real_bundle):
    r = assess(real_bundle("CVE-2024-3094"), "a", item(vendor="Tukaani", product="xz", version="5.6.1",
                                                       cpe="cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*"))
    assert r.status == S.AFFECTED


def test_malformed_source_range_does_not_decide(real_bundle):
    # curl's CNA record lists "8.4.0 affected lessThan 8.4.0" (an empty range). Only NVD's range decides.
    b = real_bundle("CVE-2023-38545")
    cna_only = assess(b, "a", item(product="curl", version="8.3.0"))
    assert cna_only.status == S.NEEDS_REVIEW
    assert any("malformed range" in x for x in cna_only.reasons)
    # With the NVD CPE identity, NVD's well-formed range (>=7.69.0 <8.4.0) decides.
    with_cpe = assess(b, "a", item(vendor="haxx", product="curl", version="8.3.0",
                                   cpe="cpe:2.3:a:haxx:libcurl:8.3.0:*:*:*:*:*:*:*"))
    assert with_cpe.status == S.AFFECTED and with_cpe.fixed_version_hint == "8.4.0"


def test_free_text_constraint_parsed_only_when_simple(real_bundle):
    r = assess(real_bundle("CVE-2024-47176"), "a", item(vendor="OpenPrinting", product="cups-browsed", version="2.0.1"))
    assert r.status == S.AFFECTED and "free-text" in r.reasons[0]
    r2 = assess(real_bundle("CVE-2024-47176"), "a", item(vendor="OpenPrinting", product="cups-browsed", version="2.0.2"))
    assert r2.status != S.AFFECTED


def test_unrelated_product_no_match(real_bundle):
    r = assess(real_bundle("CVE-2024-3094"), "a", item(vendor="PostgreSQL", product="postgresql", version="16.2"))
    assert r.status == S.NO_PRODUCT_MATCH


# ----------------------------------------------------------- synthetic edge cases


def test_sources_disagree_needs_review():
    rec = cve5_record("CVE-1999-99001", affected=[{"vendor": "Example", "product": "widget", "defaultStatus":
                      "unaffected", "versions": [{"version": "1.0.0", "lessThan": "1.2.0", "status": "affected",
                                                  "versionType": "semver"}]}])
    cpe = [{"vulnerable": True, "criteria": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.5.0"}]
    b = synthetic_bundle(record=rec, nvd=(200, nvd_response("CVE-1999-99001", cpe=cpe)))
    r = assess(b, "a", item(vendor="Example", product="widget", version="1.3.0"))  # CNA: fixed; NVD: affected
    assert r.status == S.NEEDS_REVIEW
    assert "disagree" in r.reasons[0]


def test_no_structured_data_needs_review_not_unaffected():
    b = synthetic_bundle(record=cve5_record("CVE-1999-99001", affected=[]))
    r = assess(b, "a", item(vendor="Example", product="widget", version="1.0"))
    assert r.status == S.NEEDS_REVIEW


def test_vendor_mismatch_is_not_a_match():
    b = synthetic_bundle()
    r = assess(b, "a", item(vendor="OtherCorp", product="widget", version="1.1.0"))
    assert r.status == S.NEEDS_REVIEW  # same name, different vendor -> review, never "affected"


def test_unknown_default_status_outside_ranges_is_ambiguous():
    rec = cve5_record("CVE-1999-99001", affected=[{"vendor": "Example", "product": "widget",
                      "versions": [{"version": "1.0.0", "lessThan": "1.2.0", "status": "affected",
                                    "versionType": "semver"}]}])
    b = synthetic_bundle(record=rec)
    assert assess(b, "a", item(vendor="Example", product="widget", version="0.9.0")).status == S.NEEDS_REVIEW
    assert assess(b, "a", item(vendor="Example", product="widget", version="1.1.0")).status == S.AFFECTED
