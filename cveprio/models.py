"""Typed data models shared by every stage of the pipeline.

Design rule: anything that came from a source is an ``Evidence`` item with
provenance; anything derived by deterministic code is a ``Finding`` that cites
evidence IDs; anything produced by a model lives under ``LlmAnalysis`` and is
labelled as an AI judgement. Those three never share a type.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class SourceName(StrEnum):
    CVE_ORG = "cve_org"
    NVD = "nvd"
    KEV = "cisa_kev"
    EPSS = "first_epss"
    OSV = "osv"
    UBUNTU = "ubuntu"
    REDHAT = "redhat"


class SourceStatus(StrEnum):
    OK = "ok"
    NOT_FOUND = "not_found"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    SKIPPED = "skipped"


class Truth(StrEnum):
    """Five-valued answer so 'we could not find out' never collapses into 'no'."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    RETRIEVAL_FAILED = "retrieval_failed"


class RecordState(StrEnum):
    PUBLISHED = "published"
    REJECTED = "rejected"
    RESERVED = "reserved"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"  # authoritative source could not be retrieved


class SourceOutcome(BaseModel):
    source: SourceName
    status: SourceStatus
    url: str | None = None
    retrieved_at: datetime | None = None
    from_cache: bool = False
    demo: bool = False
    http_status: int | None = None
    detail: str | None = None


class Evidence(BaseModel):
    """One verifiable item with provenance. ``excerpt`` is untrusted source text."""

    id: str
    source: SourceName
    kind: str
    summary: str
    url: str
    retrieved_at: datetime
    published: str | None = None
    updated: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    excerpt: str | None = None
    demo: bool = False
    flags: list[str] = Field(default_factory=list)


class CvssScore(BaseModel):
    version: str
    base_score: float | None
    severity: str | None
    vector: str | None
    provider: str
    provider_type: str | None = None  # NVD "Primary"/"Secondary", or "cna"/"adp"
    provider_id: str | None = None  # the source's own identifier when it differs from the display name (e.g. an org UUID)
    attack_vector: str | None = None
    attack_complexity: str | None = None
    attack_requirements: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    evidence_id: str


class Finding(BaseModel):
    """A deterministic conclusion drawn from evidence (not from a model)."""

    name: str
    value: Truth
    detail: str
    evidence_ids: list[str] = Field(default_factory=list)


class Conflict(BaseModel):
    kind: Literal["cvss_disagreement", "stale_signal", "status_mismatch", "exploitation_disagreement"]
    description: str
    evidence_ids: list[str]


class VersionSpec(BaseModel):
    version: str | None = None
    status: str | None = None
    version_type: str | None = None
    less_than: str | None = None
    less_than_or_equal: str | None = None
    changes: list[dict[str, Any]] = Field(default_factory=list)


class AffectedEntry(BaseModel):
    """CVE JSON 5 ``affected`` entry (from the CNA or an ADP container)."""

    provider: str
    vendor: str | None = None
    product: str | None = None
    package_name: str | None = None
    cpes: list[str] = Field(default_factory=list)
    default_status: str | None = None
    versions: list[VersionSpec] = Field(default_factory=list)
    evidence_id: str


class CpeMatch(BaseModel):
    """NVD configuration ``cpeMatch`` with ``vulnerable: true``."""

    criteria: str
    part: str
    vendor: str
    product: str
    version: str
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    in_and_node: bool = False  # CVE only applies in combination with another platform
    and_with: list[str] = Field(default_factory=list)  # the other platform(s) in that AND configuration
    evidence_id: str


class EpssValue(BaseModel):
    probability: float
    percentile: float
    score_date: str
    evidence_id: str


class SsvcValue(BaseModel):
    exploitation: str | None
    automatable: str | None
    technical_impact: str | None
    timestamp: str | None
    evidence_id: str


class EvidenceBundle(BaseModel):
    cve_id: str
    record_state: RecordState
    title: str | None = None
    description: str | None = None
    cwes: list[str] = Field(default_factory=list)
    cvss: list[CvssScore] = Field(default_factory=list)
    primary_cvss: CvssScore | None = None
    epss: EpssValue | None = None
    ssvc: SsvcValue | None = None
    affected: list[AffectedEntry] = Field(default_factory=list)
    cpe_matches: list[CpeMatch] = Field(default_factory=list)
    cpe_match_total: int = 0
    findings: dict[str, Finding] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)
    sources: list[SourceOutcome] = Field(default_factory=list)
    conflicts: list[Conflict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    demo: bool = False

    def evidence_ids(self) -> set[str]:
        return {e.id for e in self.evidence}

    def get(self, evidence_id: str) -> Evidence | None:
        return next((e for e in self.evidence if e.id == evidence_id), None)

    def source_status(self, source: SourceName) -> SourceStatus:
        for s in self.sources:
            if s.source == source:
                return s.status
        return SourceStatus.SKIPPED


# --------------------------------------------------------------------- inventory

Criticality = Literal["low", "medium", "high", "critical"]


class SoftwareItem(BaseModel):
    vendor: str | None = None
    product: str
    version: str
    package_name: str | None = None
    cpe: str | None = None
    purl: str | None = None  # package URL, e.g. pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
    # Distribution packages: which distro release built it ("ubuntu:24.04", "ubuntu:noble", "rhel:9") and,
    # if the package name differs from the source package the distro tracks, that source name ("openssh").
    distro: str | None = None
    source_package: str | None = None
    notes: str | None = None


class CompensatingControl(BaseModel):
    description: str
    applies_to: list[str] = Field(default_factory=lambda: ["*"], description="CVE IDs or '*'")
    effect: Literal["reduces_reachability", "mitigates_vulnerability"]


class Asset(BaseModel):
    id: str
    name: str
    software: list[SoftwareItem] = Field(default_factory=list)
    sbom: str | None = None  # path to a CycloneDX/SPDX JSON SBOM (relative to the inventory file)
    # None means "not supplied" and is treated as unknown, never as False/low.
    criticality: Criticality | None = None
    internet_facing: bool | None = None
    data_sensitivity: str | None = None
    owner: str | None = None
    compensating_controls: list[CompensatingControl] = Field(default_factory=list)


class Inventory(BaseModel):
    organization: str | None = None
    fictional: bool = False
    description: str | None = None
    assets: list[Asset]
    watchlist: list[str] = Field(default_factory=list)
    input_notes: list[str] = Field(default_factory=list)  # e.g. which SBOMs were read (filled in by the loader)


# ------------------------------------------------------------------ applicability


class ApplicabilityStatus(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    NEEDS_REVIEW = "needs_review"
    NO_PRODUCT_MATCH = "no_product_match"


class ApplicabilityResult(BaseModel):
    asset_id: str
    software: SoftwareItem
    status: ApplicabilityStatus
    matched_by: str | None = None
    reasons: list[str]
    evidence_ids: list[str] = Field(default_factory=list)
    fixed_version_hint: str | None = None
    # True when the outcome relied on an AI reading of a free-text version statement (auto-resolution).
    resolved_with_ai: bool = False
    # Context of the asset, copied from the inventory so reports can explain exposure specifically.
    asset_criticality: str | None = None
    asset_internet_facing: bool | None = None
    asset_controls: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------- LLM output


class Claim(BaseModel):
    statement: str
    type: Literal["fact", "inference"]
    evidence_ids: list[str]
    quote: str = ""  # exact words copied from a cited evidence item that support the statement


class DifficultyAssessment(BaseModel):
    rating: Literal["low", "moderate", "high", "insufficient_evidence"]
    prerequisites: list[Claim]
    complexity_factors: list[Claim]
    research_availability: list[Claim]
    open_questions: list[str]


class UsabilityAssessment(BaseModel):
    rating: Literal[
        "exploitation_reported", "public_exploit_claimed", "no_public_exploit_evidence", "insufficient_evidence"
    ]
    exploit_evidence: list[Claim]
    reliability_limitations: list[Claim]
    required_access: list[Claim]
    open_questions: list[str]


class ModelAssessment(BaseModel):
    """Exactly the shape the model must return (validated with ``extra='forbid'``)."""

    model_config = {"extra": "forbid"}

    exploit_development_difficulty: DifficultyAssessment
    existing_exploit_usability: UsabilityAssessment
    suspicious_instructions_in_evidence: bool
    summary: str


class LlmStatus(StrEnum):
    OK = "ok"
    NOT_CONFIGURED = "not_configured"
    FAILED = "failed"
    INVALID_OUTPUT = "invalid_output"
    REFUSED = "refused"
    SKIPPED = "skipped"


class ValidationIssue(BaseModel):
    path: str
    problem: str
    statement: str | None = None


class LlmAnalysis(BaseModel):
    status: LlmStatus
    provider: str
    model: str | None = None
    scripted: bool = False  # True for hand-written demo outputs (never presented as model output)
    prompt_version: str | None = None  # which version of the instructions produced this output
    detail: str | None = None
    assessment: ModelAssessment | None = None
    removed_claims: list[ValidationIssue] = Field(default_factory=list)
    rating_overrides: list[ValidationIssue] = Field(default_factory=list)
    total_claims: int = 0
    supported_claims: int = 0  # claims that passed every check (citations, quote found, numbers found)


# ------------------------------------------------------------------ prioritisation

Priority = Literal["P1", "P2", "P3", "P4"]


class Decision(BaseModel):
    label: str  # P1..P4, NEEDS_REVIEW, NOT_APPLICABLE, NO_ACTION_REJECTED, INVALID_OR_UNPUBLISHED
    priority: Priority | None
    provisional: bool
    headline: str
    factors: dict[str, str]
    trace: list[str]
    baseline_label: str
    counterfactuals: list[str]
    actions: list[str]


class VersionReadingLog(BaseModel):
    """What the AI read from free-text version statements (auto-resolution), and what the checks rejected."""

    status: str  # ok | not_run | failed | invalid_output
    provider: str
    model: str | None = None
    scripted: bool = False
    prompt_version: str
    detail: str = ""
    accepted: list[dict[str, Any]] = Field(default_factory=list)  # statement, quote, status, ranges, may_clear
    rejected: list[dict[str, str]] = Field(default_factory=list)  # statement, problem


class CveReport(BaseModel):
    schema_version: str = "1.0"
    generated_at: datetime
    tool_version: str
    mode: Literal["live", "offline_demo"]
    cve_id: str
    bundle: EvidenceBundle
    applicability: list[ApplicabilityResult] = Field(default_factory=list)
    llm: LlmAnalysis
    decision: Decision
    known: list[str]
    uncertain: list[str]
    context_supplied: bool
    summary: list[str] = Field(default_factory=list)  # 1–3 plain sentences specific to this CVE and your systems
    discovered_by: list[str] = Field(default_factory=list)  # empty = supplied by the user (watchlist/CLI)
    version_reading: VersionReadingLog | None = None  # set only when auto-resolution ran


class DiscoveryQuery(BaseModel):
    """One lookup of 'which CVEs affect this software item?'."""

    asset_id: str
    product: str
    version: str
    method: Literal["nvd_cpe", "osv_purl", "none"]
    query: str | None = None
    status: Literal["ok", "failed", "rate_limited", "not_searchable", "truncated"]
    cve_ids: list[str] = Field(default_factory=list)
    non_cve_ids: list[str] = Field(default_factory=list)  # e.g. GHSA advisories with no CVE alias
    detail: str | None = None


class OsvMatch(BaseModel):
    """OSV says this exact package version is affected by the CVE (recorded as evidence)."""

    asset_id: str
    purl: str
    advisory_ids: list[str]
    url: str
    retrieved_at: datetime


class DiscoverySummary(BaseModel):
    queries: list[DiscoveryQuery]
    total_found: int
    analyzed: list[str]
    dropped: list[str] = Field(default_factory=list)  # over the --max-cves cap
    caveats: list[str] = Field(default_factory=list)
    osv_matches: dict[str, list[OsvMatch]] = Field(default_factory=dict)  # CVE -> OSV affirmations


class RunReport(BaseModel):
    schema_version: str = "1.0"
    generated_at: datetime
    tool_version: str
    mode: Literal["live", "offline_demo"]
    organization: str | None = None
    fictional_context: bool = False
    reports: list[CveReport]
    notices: list[str]
    discovery: DiscoverySummary | None = None
