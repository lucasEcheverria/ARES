from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class ChecklistStatus(Enum):
    """Lifecycle states for a checklist item."""

    PENDING = "pending"
    RESOLVED = "resolved"
    FAILED = "failed"


class FindingStatus(Enum):
    """Outcome states for a tool finding."""

    SUCCESS = "success"
    FAIL = "fail"
    EMPTY = "empty"


class Phase(Enum):
    """Fixed reconnaissance pipeline phases (ADR-001)."""

    RECON = "recon"
    ENUMERATION = "enumeration"
    VULN_SCAN = "vuln_scan"
    REPORT = "report"


@dataclass
class ChecklistItem:
    """A single item in the agent's plan checklist.

    Attributes:
        question: The question this item must answer.
        status: Current lifecycle state of the item.
        attempts: Number of tool executions attempted so far.
        result: Output of the last tool execution, None if not yet attempted.
    """

    question: str
    status: ChecklistStatus
    attempts: int
    result: str | None


@dataclass
class Finding:
    """A persisted tool result with phase and timing context.

    Attributes:
        tool_name: Name of the tool that produced this finding.
        phase: Pipeline phase during which the finding was produced.
        status: Outcome of the tool execution.
        result: Tool output content, None if status is FAIL.
        timestamp: When the finding was produced.
    """

    tool_name: str
    phase: Phase
    status: FindingStatus
    result: str | None
    timestamp: datetime


@dataclass
class TargetState:
    """Complete session state for a single reconnaissance target.

    Structured in three sections per ADR-002 and ADR-006:
    - OBJECTIVE: immutable target definition
    - PLAN: controlled-mutable phase and checklist tracking
    - FINDINGS: append-only discovery log

    Attributes:
        raw_prompt: Literal user input that initiated the session.
        target: IP or URL extracted from the prompt.
        target_context: Prior knowledge the user has about the target, if any.
        current_phase: Active pipeline phase.
        global_checklist: Session-wide checklist generated at startup.
        phase_checklist: Phase-specific checklist generated on phase entry.
        confirmed: Promoted findings, always present in memory.
        raw: Recent raw findings, capped to last N entries.
    """

    # OBJECTIVE — immutable, written once at session start
    raw_prompt: str
    target: str
    target_context: str | None

    # PLAN — controlled-mutable, updated as phases progress
    current_phase: Phase
    global_checklist: list[ChecklistItem]
    phase_checklist: list[ChecklistItem]

    # FINDINGS — append-only, confirmed items never removed
    confirmed: list[Finding]
    raw: list[Finding]
