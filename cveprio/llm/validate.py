"""Validate model output against the schema *and* against the evidence.

1. Parse JSON (tolerating code fences / <think> blocks some local models emit).
2. Validate the shape with Pydantic (unknown keys rejected).
3. Remove every claim that has no citations or cites an ID not in the bundle.
4. Override ratings that contradict deterministic findings (e.g. "exploitation
   reported" when no source reports exploitation) and record each override.

The output of this module is the only model content that reaches a report.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import ValidationError

from cveprio.models import Claim, EvidenceBundle, ModelAssessment, Truth, ValidationIssue

MAX_STATEMENT = 600
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class InvalidModelOutput(ValueError):
    pass


def extract_json(raw: str) -> dict[str, Any]:
    text = re.sub(r"<think>.*?</think>", "", raw or "", flags=re.DOTALL).strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, flags=re.DOTALL)
    if fence:
        text = fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise InvalidModelOutput("no JSON object in model output")
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise InvalidModelOutput(f"model output is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InvalidModelOutput("model output JSON is not an object")
    return data


def parse_assessment(raw: str) -> ModelAssessment:
    data = extract_json(raw)
    try:
        return ModelAssessment.model_validate(data)
    except ValidationError as exc:
        errs = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:8])
        raise InvalidModelOutput(f"schema validation failed: {errs}") from exc


def _filter(claims: list[Claim], path: str, valid_ids: set[str], removed: list[ValidationIssue]) -> list[Claim]:
    kept = []
    for i, c in enumerate(claims):
        c.statement = _CTRL.sub("", c.statement).strip()[:MAX_STATEMENT]
        if not c.evidence_ids:
            removed.append(ValidationIssue(path=f"{path}[{i}]", problem="no evidence cited", statement=c.statement))
            continue
        bad = [x for x in c.evidence_ids if x not in valid_ids]
        if bad:
            removed.append(ValidationIssue(path=f"{path}[{i}]", problem=f"cites unknown evidence ID(s): {bad}",
                                           statement=c.statement))
            continue
        kept.append(c)
    return kept


def validate_against_evidence(
    a: ModelAssessment, bundle: EvidenceBundle
) -> tuple[ModelAssessment, list[ValidationIssue], list[ValidationIssue], int, int]:
    valid = bundle.evidence_ids()
    removed: list[ValidationIssue] = []
    overrides: list[ValidationIssue] = []
    d, u = a.exploit_development_difficulty, a.existing_exploit_usability
    total = sum(len(x) for x in (d.prerequisites, d.complexity_factors, d.research_availability,
                                 u.exploit_evidence, u.reliability_limitations, u.required_access))

    d.prerequisites = _filter(d.prerequisites, "difficulty.prerequisites", valid, removed)
    d.complexity_factors = _filter(d.complexity_factors, "difficulty.complexity_factors", valid, removed)
    d.research_availability = _filter(d.research_availability, "difficulty.research_availability", valid, removed)
    u.exploit_evidence = _filter(u.exploit_evidence, "usability.exploit_evidence", valid, removed)
    u.reliability_limitations = _filter(u.reliability_limitations, "usability.reliability_limitations", valid,
                                        removed)
    u.required_access = _filter(u.required_access, "usability.required_access", valid, removed)
    supported = total - len(removed)

    exploited = bundle.findings.get("exploited_in_wild")
    claimed = bundle.findings.get("public_exploit_claimed")
    is_exploited = bool(exploited and exploited.value == Truth.TRUE)
    is_claimed = bool(claimed and claimed.value == Truth.TRUE)

    def override(path: str, old: str, new: str, why: str) -> str:
        overrides.append(ValidationIssue(path=path, problem=f"rating '{old}' → '{new}': {why}"))
        return new

    if u.rating == "exploitation_reported" and not is_exploited:
        u.rating = override("usability.rating", u.rating,  # type: ignore[assignment]
                            "public_exploit_claimed" if is_claimed else "insufficient_evidence",
                            "no source in the bundle reports in-the-wild exploitation")
    elif u.rating == "public_exploit_claimed" and not (is_claimed or is_exploited):
        u.rating = override("usability.rating", u.rating, "insufficient_evidence",  # type: ignore[assignment]
                            "no exploit-tagged reference or SSVC PoC signal in the bundle")
    elif u.rating == "no_public_exploit_evidence" and (is_claimed or is_exploited):
        u.rating = override("usability.rating", u.rating,  # type: ignore[assignment]
                            "exploitation_reported" if is_exploited else "public_exploit_claimed",
                            "contradicts deterministic findings from KEV/SSVC/NVD references")
    if u.rating != "insufficient_evidence" and not (u.exploit_evidence or u.required_access):
        u.rating = override("usability.rating", u.rating, "insufficient_evidence",  # type: ignore[assignment]
                            "no supported claims remain for this assessment")
    if d.rating != "insufficient_evidence" and not (d.prerequisites or d.complexity_factors
                                                     or d.research_availability):
        d.rating = override("difficulty.rating", d.rating, "insufficient_evidence",  # type: ignore[assignment]
                            "no supported claims remain for this assessment")
    a.summary = _CTRL.sub("", a.summary).strip()[:1200]
    d.open_questions = [_CTRL.sub("", q)[:300] for q in d.open_questions[:10]]
    u.open_questions = [_CTRL.sub("", q)[:300] for q in u.open_questions[:10]]
    return a, removed, overrides, total, supported
