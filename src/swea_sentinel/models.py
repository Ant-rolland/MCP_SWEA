"""Versioned, evidence-aware Pydantic contracts shared by MCP adapters and services."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class GovernanceProfile(StrEnum):
    OBSERVE = "observe"
    GOVERN = "govern"
    ENFORCE = "enforce"


class LifecycleState(StrEnum):
    DISCOVERED = "DISCOVERED"
    QUALIFIED = "QUALIFIED"
    ASSESSMENT_PENDING = "ASSESSMENT_PENDING"
    ADVISED = "ADVISED"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    VERIFIED = "VERIFIED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    COMPLETED = "COMPLETED"


class SWEADomain(StrEnum):
    ARCHITECTURE = "architecture"
    DATA_CONTRACTS = "data_contracts"
    CODE_QUALITY = "code_quality"
    ORCHESTRATION = "orchestration"
    FINOPS = "finops"
    SECURITY = "security"
    PRIVACY_COMPLIANCE = "privacy_compliance"
    RESILIENCE = "resilience"
    PERFORMANCE_SCALABILITY = "performance_scalability"
    DATABASE_MIGRATIONS = "database_migrations"
    DEVOPS_OBSERVABILITY = "devops_observability"
    TESTING_VERIFICATION = "testing_verification"


class DataOrigin(StrEnum):
    VERIFIED_SOURCE = "verified_source"
    EXTERNAL_UNVERIFIED = "external_unverified"
    MOCK = "mock"
    SYNTHETIC = "synthetic"
    UNKNOWN = "unknown"


class QualificationStatus(StrEnum):
    QUALIFIED = "qualified"
    UNQUALIFIED = "unqualified"
    REQUIRES_REVIEW = "requires_review"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    PROVEN = "PROVEN"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    HEURISTIC = "HEURISTIC"
    UNKNOWN = "UNKNOWN"


class ExecutionStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ProjectInitializeInput(ContractModel):
    path: str = Field(min_length=1, max_length=4096)
    name: str | None = Field(default=None, max_length=200)


class ProjectRefreshInput(ContractModel):
    project_id: str = Field(min_length=1, max_length=64)


class ProjectReferenceInput(ContractModel):
    project_id: str = Field(min_length=1, max_length=64)


class Task(ContractModel):
    task_id: str = Field(default_factory=lambda: str(uuid4()))
    project_id: str
    title: str = Field(min_length=1, max_length=300)
    state: LifecycleState = LifecycleState.DISCOVERED
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Evidence(ContractModel):
    evidence_id: str = Field(default_factory=lambda: str(uuid4()))
    kind: str = Field(min_length=1, max_length=80)
    description: str = Field(min_length=1, max_length=2000)
    origin: DataOrigin = DataOrigin.UNKNOWN
    qualification: QualificationStatus = QualificationStatus.REQUIRES_REVIEW
    source_path: str | None = Field(default=None, max_length=4096)
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime = Field(default_factory=utc_now)


class Finding(ContractModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    domain: SWEADomain
    code: str = Field(min_length=1, max_length=100)
    severity: Severity
    confidence: Confidence
    title: str = Field(min_length=1, max_length=300)
    location: str | None = Field(default=None, max_length=4096)
    evidence_ids: list[str] = Field(default_factory=list)
    recommendation: str = Field(min_length=1, max_length=4000)
    status: FindingStatus = FindingStatus.OPEN


class ToolResult(ContractModel):
    schema_version: str = SCHEMA_VERSION
    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    task_id: str | None = None
    project_id: str | None = None
    lifecycle_state: LifecycleState | None = None
    status: ExecutionStatus
    result: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    duration_ms: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)


class ProjectStatus(ContractModel):
    project_id: str
    name: str
    root_path: str
    created_at: datetime
    last_indexed_at: datetime | None = None
    indexed_files: int = 0
    status: str = "active"
