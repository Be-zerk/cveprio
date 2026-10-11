"""Distribution advisories (Ubuntu, Red Hat) decide applicability for distribution packages."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cveprio.applicability import assess
from cveprio.models import ApplicabilityStatus as S
from cveprio.models import SoftwareItem, SourceName, SourceOutcome, SourceStatus
from cveprio.normalize import build_bundle
from cveprio.sources import EpssBatch, KevCatalog, SourceData
from tests.conftest import cve5_record

NOW = datetime(2026, 10, 11, tzinfo=UTC)
CVE = "CVE-1999-99001"


def _out(src, status=SourceStatus.OK):
    return SourceOutcome(source=src, status=status, url="https://example.invalid/x", retrieved_at=NOW)


def bundle(ubuntu=None, redhat=None):
    distros = []
    if ubuntu is not None:
        distros.append(SourceData(_out(SourceName.UBUNTU), {"packages": ubuntu, "updated_at": "2026-09-01"}))
    if redhat is not None:
        distros.append(SourceData(_out(SourceName.REDHAT), redhat))
    rec = cve5_record(CVE, affected=[{"vendor": "OpenBSD", "product": "OpenSSH", "defaultStatus": "unaffected",
                                      "versions": [{"version": "8.5p1", "lessThanOrEqual": "9.7p1",
                                                    "status": "affected", "versionType": "custom"}]}])
    return build_bundle(CVE, SourceData(_out(SourceName.CVE_ORG), {"record": rec}),
                        SourceData(_out(SourceName.NVD, SourceStatus.NOT_FOUND)),
                        KevCatalog(_out(SourceName.KEV), {}, "x", None), EpssBatch({}, {}), demo=False, now=NOW,
                        distros=distros)


UBUNTU_OPENSSH = [{"name": "openssh", "statuses": [
    {"release": "noble", "status": "released", "description": "1:9.6p1-3ubuntu13.3"},
    {"release": "jammy", "status": "released", "description": "1:8.9p1-3ubuntu0.10"},
    {"release": "focal", "status": "not-affected", "description": "introduced in v8.5p1"},
    {"release": "plucky", "status": "needed", "description": ""},
]}]


def ubuntu_item(version, release="24.04"):
    return SoftwareItem(product="OpenSSH", package_name="openssh-server", version=version, distro=f"ubuntu:{release}")


@pytest.mark.parametrize("version,release,status", [
    ("1:9.6p1-3ubuntu13.4", "24.04", S.NOT_AFFECTED),   # newer than Ubuntu's fixed build
    ("1:9.6p1-3ubuntu13.3", "noble", S.NOT_AFFECTED),   # exactly the fixed build; codename accepted
    ("1:9.6p1-3ubuntu13", "24.04", S.AFFECTED),         # older than the fix
    ("1:8.2p1-4ubuntu0.11", "20.04", S.NOT_AFFECTED),   # Ubuntu says not affected in focal
    ("1:9.9p1-3ubuntu3", "25.04", S.AFFECTED),          # fix still needed
])
def test_ubuntu_verdicts(version, release, status):
    r = assess(bundle(ubuntu=UBUNTU_OPENSSH), "a", ubuntu_item(version, release))
    assert r.status == status, r.reasons
    assert "UBUNTU" in r.evidence_ids


def test_affected_ubuntu_build_gets_fixed_version_hint():
    r = assess(bundle(ubuntu=UBUNTU_OPENSSH), "a", ubuntu_item("1:9.6p1-3ubuntu13"))
    assert r.fixed_version_hint == "1:9.6p1-3ubuntu13.3"


def test_without_distro_data_it_stays_needs_review():
    r = assess(bundle(), "a", ubuntu_item("1:9.6p1-3ubuntu13.4"))
    assert r.status == S.NEEDS_REVIEW


def test_purl_distro_qualifier_is_understood():
    item = SoftwareItem(product="openssh-server", version="1:9.6p1-3ubuntu13.4",
                        purl="pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.4?distro=ubuntu-24.04")
    assert assess(bundle(ubuntu=UBUNTU_OPENSSH), "a", item).status == S.NOT_AFFECTED


RHEL = {"affected_release": [{"product": "Red Hat Enterprise Linux 9", "package": "openssh-0:8.7p1-38.el9_4.1",
                              "cpe": "cpe:/o:redhat:enterprise_linux:9"},
                             {"product": "Red Hat Enterprise Linux 9.2 Extended Update Support",
                              "package": "openssh-0:8.7p1-30.el9_2.4"}],
        "package_state": [{"product": "Red Hat Enterprise Linux 8", "fix_state": "Not affected", "package": "openssh"},
                          {"product": "Red Hat Enterprise Linux 7", "fix_state": "Out of support scope",
                           "package": "openssh"}]}


@pytest.mark.parametrize("version,release,status", [
    ("8.7p1-38.el9_4.1", "9", S.NOT_AFFECTED),
    ("0:8.7p1-38.el9_4.4", "9", S.NOT_AFFECTED),
    ("8.7p1-34.el9", "9", S.AFFECTED),
    ("8.0p1-19.el8", "8", S.NOT_AFFECTED),
    ("7.4p1-23.el7", "7", S.AFFECTED),
])
def test_redhat_verdicts(version, release, status):
    item = SoftwareItem(product="openssh", package_name="openssh", version=version, distro=f"rhel:{release}")
    r = assess(bundle(redhat=RHEL), "a", item)
    assert r.status == status, r.reasons
    assert "REDHAT" in r.evidence_ids


def test_distribution_failure_is_reported_not_treated_as_safe():
    b = build_bundle(CVE, SourceData(_out(SourceName.CVE_ORG), {"record": cve5_record(CVE)}),
                     SourceData(_out(SourceName.NVD, SourceStatus.NOT_FOUND)),
                     KevCatalog(_out(SourceName.KEV), {}, "x", None), EpssBatch({}, {}), demo=False, now=NOW,
                     distros=[SourceData(_out(SourceName.UBUNTU, SourceStatus.FAILED))])
    assert b.source_status(SourceName.UBUNTU) == SourceStatus.FAILED
    assert any("Partial result" in w for w in b.warnings)
