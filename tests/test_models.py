import pytest
from pydantic import ValidationError

from swea_sentinel.models import (
    Confidence,
    DataOrigin,
    ExecutionStatus,
    Evidence,
    Finding,
    LifecycleState,
    QualificationStatus,
    Severity,
    Task,
    ToolResult,
)


def test_tool_result_has_version_and_execution_id():
    result = ToolResult(status=ExecutionStatus.COMPLETED)
    assert result.schema_version == "1.0"
    assert result.execution_id


def test_finding_requires_explicit_confidence_and_severity():
    finding = Finding(
        domain="security", code="TEST", severity=Severity.HIGH,
        confidence=Confidence.HEURISTIC, title="Example",
        recommendation="Review manually",
    )
    assert finding.confidence is Confidence.HEURISTIC


def test_contract_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        ToolResult(status="completed", unexpected="not allowed")


def test_unqualified_evidence_is_never_assumed_verified():
    evidence = Evidence(kind="external_api", description="Payload from an external source")
    assert evidence.origin is DataOrigin.UNKNOWN
    assert evidence.qualification is QualificationStatus.REQUIRES_REVIEW


def test_task_starts_in_discovered_lifecycle_state():
    task = Task(project_id="project-1", title="Review schema change")
    assert task.state is LifecycleState.DISCOVERED


def test_finding_rejects_unknown_swea_domain():
    with pytest.raises(ValidationError):
        Finding(
            domain="invented_domain", code="TEST", severity=Severity.LOW,
            confidence=Confidence.UNKNOWN, title="Example",
            recommendation="Classify this finding",
        )
