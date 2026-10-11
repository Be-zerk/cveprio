"""AC15–AC18: rule table, missing context, counterfactuals, baseline, bounded AI influence."""

from __future__ import annotations

import pytest

from cveprio.models import (
    ApplicabilityResult,
    ApplicabilityStatus,
    Asset,
    Claim,
    CompensatingControl,
    DifficultyAssessment,
    LlmAnalysis,
    LlmStatus,
    ModelAssessment,
    RecordState,
    SoftwareItem,
    UsabilityAssessment,
)
from cveprio.prioritize import RuleInputs, decide, prioritize
from tests.conftest import cve5_record, kev_feed, nvd_response, synthetic_bundle

P = RecordState.PUBLISHED


@pytest.mark.parametrize("exploitation,severity,exposure,label", [
    ("confirmed", "low", "standard", "P1"),           # KEV beats severity
    ("confirmed", "critical", "reduced", "P2"),       # a control never drops confirmed below P2
    ("elevated", "medium", "high", "P2"),           # P1 needs confirmed attacks or high/critical severity
    ("elevated", "high", "high", "P1"),
    ("claimed_unverified", "medium", "standard", "P3"),  # one exploit-tagged link alone is a weak signal
    ("claimed_unverified", "medium", "high", "P2"),
    ("claimed_unverified", "low", "high", "P3"),     # low severity capped at P3 unless attacks confirmed
    ("elevated", "low", "high", "P3"),
    ("confirmed", "low", "high", "P1"),             # the cap never applies to confirmed attacks
    ("elevated", "critical", "standard", "P2"),
    ("low_observed", "critical", "standard", "P3"),
    ("low_observed", "critical", "high", "P2"),
    ("low_observed", "medium", "standard", "P4"),
    ("low_observed", "low", "reduced", "P4"),
    ("low_observed", "unscored", "standard", "P3"),   # unscored handled conservatively
    ("evidence_incomplete", "low", "standard", "P2"),  # failures don't silently lower priority
    ("confirmed", "critical", "needs_review", "NEEDS_REVIEW"),
    ("confirmed", "critical", "not_affected", "NOT_APPLICABLE"),
    ("elevated", "high", "not_in_inventory", "NOT_IN_INVENTORY"),
])
def test_rule_table(exploitation, severity, exposure, label):
    got, _, _, trace = decide(RuleInputs(P, exploitation, severity, exposure))
    assert got == label
    assert trace  # every decision explains itself


@pytest.mark.parametrize("state,label", [(RecordState.REJECTED, "NO_ACTION_REJECTED"),
                                         (RecordState.RESERVED, "INVALID_OR_UNPUBLISHED"),
                                         (RecordState.NOT_FOUND, "INVALID_OR_UNPUBLISHED"),
                                         (RecordState.UNKNOWN, "RETRIEVAL_FAILED")])
def test_non_published_records_get_no_priority(state, label):
    got, p, _, _ = decide(RuleInputs(state, "confirmed", "critical", "high"))
    assert got == label and p is None


def test_missing_context_is_provisional_and_not_invented():
    d = prioritize(synthetic_bundle(), None, [], None)
    assert d.provisional and d.factors["exposure"] == "not_assessed"
    assert any("No inventory" in t for t in d.trace)
    assert any("internet-facing" in c for c in d.counterfactuals)


def _asset(**kw):
    return Asset(id="a1", name="x", software=[SoftwareItem(vendor="Example", product="widget", version="1.1.0")], **kw)


def _affected():
    return [ApplicabilityResult(asset_id="a1", software=SoftwareItem(vendor="Example", product="widget",
                                version="1.1.0"), status=ApplicabilityStatus.AFFECTED, reasons=["test"],
                                fixed_version_hint="1.4.2")]


def test_partial_context_counts_as_unknown_not_low():
    a = _asset(criticality="medium")  # internet_facing not supplied
    d = prioritize(synthetic_bundle(), None, _affected(), {"a1": a})
    assert d.factors["exposure"] == "context_unknown" and d.provisional
    assert any("internet exposure is not recorded" in t for t in d.trace)


def test_business_context_changes_priority():
    b = synthetic_bundle()  # high severity, no exploitation signal, EPSS 0.01
    internal = prioritize(b, None, _affected(), {"a1": _asset(criticality="low", internet_facing=False)})
    exposed = prioritize(b, None, _affected(), {"a1": _asset(criticality="low", internet_facing=True)})
    controlled = prioritize(b, None, _affected(), {"a1": _asset(criticality="low", internet_facing=True,
                            compensating_controls=[CompensatingControl(description="WAF rule",
                                                                       effect="reduces_reachability")])})
    assert (internal.label, exposed.label, controlled.label) == ("P3", "P2", "P4")
    assert any("does not verify" in t for t in controlled.trace)
    assert any("1.4.2" in a for a in exposed.actions)


def test_baseline_is_severity_only():
    b = synthetic_bundle(nvd=(200, nvd_response("CVE-1999-99001", nvd_score=9.8)))
    d = prioritize(b, None, [], None)
    assert d.baseline_label == "P1" and d.label == "P3"  # no exploitation evidence: contextual differs


def test_kev_counterfactual_and_listing():
    b = synthetic_bundle()
    d = prioritize(b, None, _affected(), {"a1": _asset(criticality="low", internet_facing=False)})
    assert any("attacked" in c and "P1" in c for c in d.counterfactuals)
    b2 = synthetic_bundle(kev=(200, kev_feed(["CVE-1999-99001"])))
    d2 = prioritize(b2, None, _affected(), {"a1": _asset(criticality="low", internet_facing=False)})
    assert d2.label == "P1" and any("CISA" in a and "Apply updates per vendor instructions" in a for a in d2.actions)


def _llm(rating: str, n_claims: int) -> LlmAnalysis:
    c = [Claim(statement=f"c{i}", type="inference", evidence_ids=["CVE.desc"]) for i in range(n_claims)]
    a = ModelAssessment(
        exploit_development_difficulty=DifficultyAssessment(rating=rating, prerequisites=c, complexity_factors=[],
                                                            research_availability=[], open_questions=[]),
        existing_exploit_usability=UsabilityAssessment(rating="insufficient_evidence", exploit_evidence=[],
                                                       reliability_limitations=[], required_access=[], open_questions=[]),
        suspicious_instructions_in_evidence=False, summary="")
    return LlmAnalysis(status=LlmStatus.OK, provider="stub", assessment=a)


def test_ai_can_only_raise_from_low_observed_with_cited_support():
    b = synthetic_bundle()
    base = prioritize(b, None, [], None)
    assert base.factors["exploitation"] == "low_observed"
    assert prioritize(b, _llm("low", 1), [], None).factors["exploitation"] == "low_observed"  # too little support
    bumped = prioritize(b, _llm("low", 2), [], None)
    assert bumped.factors["exploitation"] == "elevated" and any("AI judgement" in t for t in bumped.trace)
    assert prioritize(b, _llm("high", 5), [], None).label == base.label  # can never lower


def test_ai_has_no_effect_when_exploitation_confirmed():
    b = synthetic_bundle(kev=(200, kev_feed(["CVE-1999-99001"])))
    assert prioritize(b, _llm("high", 5), [], None).label == "P1"


def test_rejected_record_actions(real_bundle):
    d = prioritize(real_bundle("CVE-2026-11415"), None, [], None)
    assert d.label == "NO_ACTION_REJECTED" and "rejected" in d.actions[0]
    assert d.factors == {"exploitation": "n/a", "severity": "n/a", "exposure": "n/a"}


def test_unscored_cvss_does_not_become_low():
    b = synthetic_bundle(record=cve5_record("CVE-1999-99001", cvss=None))
    d = prioritize(b, None, [], None)
    assert d.factors["severity"] == "unscored" and d.priority == "P3" and d.baseline_label == "UNSCORED"
