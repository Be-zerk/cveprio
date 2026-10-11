"""JSON Schema sent to providers that support constrained output.

Hand-written (rather than generated) so it stays within the subset that both the
Anthropic structured-outputs feature and OpenAI-compatible ``json_schema`` modes
accept: objects with ``additionalProperties: false`` and every property required,
string enums, arrays of objects. Pydantic (``ModelAssessment``) re-validates the
result locally regardless of what the provider promises.
"""

from __future__ import annotations

from typing import Any

CLAIM: dict[str, Any] = {
    "type": "object",
    "properties": {
        "statement": {"type": "string"},
        "type": {"type": "string", "enum": ["fact", "inference"]},
        "evidence_ids": {"type": "array", "items": {"type": "string"}},
        "quote": {"type": "string"},
    },
    "required": ["statement", "type", "evidence_ids", "quote"],
    "additionalProperties": False,
}


def _claims() -> dict[str, Any]:
    return {"type": "array", "items": CLAIM}


QUESTIONS = {"type": "array", "items": {"type": "string"}}

ASSESSMENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "exploit_development_difficulty": {
            "type": "object",
            "properties": {
                "rating": {"type": "string", "enum": ["low", "moderate", "high", "insufficient_evidence"]},
                "prerequisites": _claims(),
                "complexity_factors": _claims(),
                "research_availability": _claims(),
                "open_questions": QUESTIONS,
            },
            "required": ["rating", "prerequisites", "complexity_factors", "research_availability", "open_questions"],
            "additionalProperties": False,
        },
        "existing_exploit_usability": {
            "type": "object",
            "properties": {
                "rating": {"type": "string", "enum": ["exploitation_reported", "public_exploit_claimed",
                                                      "no_public_exploit_evidence", "insufficient_evidence"]},
                "exploit_evidence": _claims(),
                "reliability_limitations": _claims(),
                "required_access": _claims(),
                "open_questions": QUESTIONS,
            },
            "required": ["rating", "exploit_evidence", "reliability_limitations", "required_access",
                         "open_questions"],
            "additionalProperties": False,
        },
        "suspicious_instructions_in_evidence": {"type": "boolean"},
        "summary": {"type": "string"},
    },
    "required": ["exploit_development_difficulty", "existing_exploit_usability",
                 "suspicious_instructions_in_evidence", "summary"],
    "additionalProperties": False,
}
