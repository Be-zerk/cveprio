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


MIN_QUOTE_WORDS = 3
_NUMBERS = re.compile(r"\b\d+(?:\.\d+)+[a-z0-9-]*\b|\b\d{4}-\d{2}-\d{2}\b")


def _norm(text: str) -> str:
    text = text.lower().replace("\u2019", "'").replace("\u2018", "'").replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("\u2013", "-").replace("\u2014", "-")
    return re.sub(r"\s+", " ", text).strip()


def evidence_texts(bundle: EvidenceBundle) -> dict[str, str]:
    """Normalised text of each evidence item: what a quote or number can be checked against."""
    out = {}
    for e in bundle.evidence:
        fields = " ".join(str(v) for v in e.fields.values() if v not in (None, "", [], {}))
        out[e.id] = _norm(" ".join([e.summary, e.excerpt or "", fields, json.dumps(e.fields, default=str)]))
    return out


def _filter(claims: list[Claim], path: str, valid_ids: set[str], removed: list[ValidationIssue],
            texts: dict[str, str]) -> list[Claim]:
    kept = []
    for i, c in enumerate(claims):
        c.statement = _CTRL.sub("", c.statement).strip()[:MAX_STATEMENT]
        c.quote = _CTRL.sub("", c.quote or "").strip()[:MAX_STATEMENT]
        where = f"{path}[{i}]"

        def drop(problem: str, claim: Claim = c, at: str = where) -> None:
            removed.append(ValidationIssue(path=at, problem=problem, statement=claim.statement))

        if not c.evidence_ids:
            drop("no evidence cited")
            continue
        bad = [x for x in c.evidence_ids if x not in valid_ids]
        if bad:
            drop(f"cites unknown evidence ID(s): {bad}")
            continue
        cited = " ".join(texts.get(x, "") for x in c.evidence_ids)
        quote = _norm(c.quote).strip(" .,;:\"'")
        if len(quote.split()) < MIN_QUOTE_WORDS:
            drop("no supporting quote given")
            continue
        if quote not in cited:
            drop("its quote does not appear in the cited evidence")
            continue
        missing = [n for n in _NUMBERS.findall(c.statement) if n.lower() not in cited]
        if missing:
            drop(f"mentions {', '.join(missing[:3])}, which the cited evidence does not contain")
            continue
        kept.append(c)
    return kept


def usability_from_facts(bundle: EvidenceBundle) -> str:
    """Attack-evidence rating supported by the deterministic findings (KEV, CISA SSVC, exploit references)."""
    f = bundle.findings
    exploited, claimed = f.get("exploited_in_wild"), f.get("public_exploit_claimed")
    if exploited and exploited.value == Truth.TRUE:
        return "exploitation_reported"
    if claimed and claimed.value == Truth.TRUE:
        return "public_exploit_claimed"
    if any(x is None or x.value == Truth.RETRIEVAL_FAILED for x in (exploited, claimed)):
        return "insufficient_evidence"
    return "no_public_exploit_evidence"


def validate_against_evidence(
    a: ModelAssessment, bundle: EvidenceBundle
) -> tuple[ModelAssessment, list[ValidationIssue], list[ValidationIssue], int, int]:
    valid = bundle.evidence_ids()
    removed: list[ValidationIssue] = []
    overrides: list[ValidationIssue] = []
    d, u = a.exploit_development_difficulty, a.existing_exploit_usability
    total = sum(len(x) for x in (d.prerequisites, d.complexity_factors, d.research_availability,
                                 u.exploit_evidence, u.reliability_limitations, u.required_access))

    texts = evidence_texts(bundle)
    d.prerequisites = _filter(d.prerequisites, "difficulty.prerequisites", valid, removed, texts)
    d.complexity_factors = _filter(d.complexity_factors, "difficulty.complexity_factors", valid, removed, texts)
    d.research_availability = _filter(d.research_availability, "difficulty.research_availability", valid, removed, texts)
    u.exploit_evidence = _filter(u.exploit_evidence, "usability.exploit_evidence", valid, removed, texts)
    u.reliability_limitations = _filter(u.reliability_limitations, "usability.reliability_limitations", valid,
                                        removed, texts)
    u.required_access = _filter(u.required_access, "usability.required_access", valid, removed, texts)
    supported = total - len(removed)

    def override(path: str, old: str, new: str, why: str) -> str:
        overrides.append(ValidationIssue(path=path, problem=f"rating '{old}' → '{new}': {why}"))
        return new

    # The attack-evidence rating comes from the sources, not the model. The model is no longer asked for it;
    # if it sends one that differs, the correction is recorded so contradictions stay visible.
    facts = usability_from_facts(bundle)
    if "rating" in u.model_fields_set and u.rating != facts:
        if u.rating == "exploitation_reported":
            why = "no source in the bundle reports in-the-wild exploitation"
        elif u.rating == "public_exploit_claimed" and facts != "exploitation_reported":
            why = "no exploit-tagged reference or SSVC PoC signal in the bundle"
        else:
            why = "contradicts deterministic findings from KEV/SSVC/NVD references"
        override("usability.rating", u.rating, facts, why)
    u.rating = facts  # type: ignore[assignment]
    if d.rating != "insufficient_evidence" and not (d.prerequisites or d.complexity_factors
                                                     or d.research_availability):
        d.rating = override("difficulty.rating", d.rating, "insufficient_evidence",  # type: ignore[assignment]
                            "no supported claims remain for this assessment")
    a.summary = _CTRL.sub("", a.summary).strip()[:1200]
    d.open_questions = [_CTRL.sub("", q)[:300] for q in d.open_questions[:10]]
    u.open_questions = [_CTRL.sub("", q)[:300] for q in u.open_questions[:10]]
    return a, removed, overrides, total, supported
