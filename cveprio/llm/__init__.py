"""LLM-assisted analysis: prompt -> provider -> validation -> ``LlmAnalysis``."""

from __future__ import annotations

from cveprio.llm.prompt import PROMPT_VERSION, SYSTEM_PROMPT, build_user_prompt
from cveprio.llm.providers import Provider, ProviderError
from cveprio.llm.schema import ASSESSMENT_SCHEMA
from cveprio.llm.validate import InvalidModelOutput, parse_assessment, validate_against_evidence
from cveprio.models import EvidenceBundle, LlmAnalysis, LlmStatus, RecordState

_ERROR_STATUS = {"not_configured": LlmStatus.NOT_CONFIGURED, "refused": LlmStatus.REFUSED}


def analyze(bundle: EvidenceBundle, provider: Provider) -> LlmAnalysis:
    if provider.name == "none":
        return LlmAnalysis(status=LlmStatus.NOT_CONFIGURED, provider="none",
                           detail="AI assessment not run (no model provider configured). All other sections are "
                                  "deterministic and unaffected.")
    if bundle.record_state != RecordState.PUBLISHED:
        return LlmAnalysis(status=LlmStatus.SKIPPED, provider=provider.name, model=provider.model,
                           detail=f"Not run: record is {bundle.record_state}.")
    try:
        resp = provider.complete(bundle.cve_id, SYSTEM_PROMPT, build_user_prompt(bundle), ASSESSMENT_SCHEMA)
    except ProviderError as err:
        return LlmAnalysis(status=_ERROR_STATUS.get(err.kind, LlmStatus.FAILED), provider=provider.name,
                           model=provider.model, detail=f"{err.kind}: {err}")
    try:
        parsed = parse_assessment(resp.text)
    except InvalidModelOutput as err:
        return LlmAnalysis(status=LlmStatus.INVALID_OUTPUT, provider=provider.name, model=resp.model,
                           scripted=resp.scripted, prompt_version=PROMPT_VERSION, detail=str(err)[:500])
    assessment, removed, overrides, total, supported = validate_against_evidence(parsed, bundle)
    return LlmAnalysis(status=LlmStatus.OK, provider=provider.name, model=resp.model, scripted=resp.scripted,
                       prompt_version=PROMPT_VERSION, assessment=assessment, removed_claims=removed, rating_overrides=overrides,
                       total_claims=total, supported_claims=supported)
