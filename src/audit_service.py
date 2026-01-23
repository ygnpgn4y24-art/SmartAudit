import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from src.logic import analyze_code_with_ai, run_heuristic_checks
from src.logger_config import logger


# === Data Models ===


@dataclass
class Vulnerability:
    """
    Align with the final interface doc (Member 1 DB + Member 5 API).
    """

    id: int
    audit_report_id: int
    name: str
    severity: str
    description: str
    recommendation: str
    line_number: int
    function_name: str


@dataclass
class AuditReport:
    """
    Align with the final interface doc (Member 1 DB + Member 5 API).
    """

    id: int
    user_id: int
    contract_code: str
    contract_name: str
    heuristic_results: str  # JSON string
    ai_analysis: str
    severity_score: float  # 0-10
    vulnerabilities_count: int
    created_at: datetime
    analysis_duration: float  # seconds
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    # Extra fields for our current UI needs; DB can ignore / not persist these.
    functions: List[Dict[str, Any]] = field(default_factory=list)
    extra_metadata: Dict[str, Any] = field(default_factory=dict)


# === Repository Interface (for Member 1) ===


@runtime_checkable
class AuditRepository(Protocol):
    """
    Storage abstraction for audit reports.

    Member 1 should provide a concrete implementation using SQLAlchemy models
    defined in `src.database` and plug it into this module via `set_audit_repository(...)`.
    """

    def create_audit(self, audit: AuditReport) -> AuditReport:
        ...

    def list_audits_for_user(
        self,
        user_id: int,
        limit: int = 50,
        offset: int = 0,
    ) -> List[AuditReport]:
        ...

    def get_audit_by_id(
        self,
        audit_id: int,
        user_id: Optional[int] = None,
    ) -> Optional[AuditReport]:
        ...


class InMemoryAuditRepository:
    """
    Simple in-memory implementation for development / demo.
    This is NOT persistent and should be replaced by a DB-backed repo.
    """

    def __init__(self) -> None:
        self._items: Dict[int, AuditReport] = {}
        self._next_audit_id = 1
        self._next_vuln_id = 1

    def create_audit(self, audit: AuditReport) -> AuditReport:
        # Allocate incremental IDs to match the final interface (int PK).
        audit.id = self._next_audit_id
        self._next_audit_id += 1

        # Assign PKs to vulnerabilities if any
        for v in audit.vulnerabilities:
            v.id = self._next_vuln_id
            v.audit_report_id = audit.id
            self._next_vuln_id += 1

        self._items[audit.id] = audit
        return audit

    def list_audits_for_user(
        self,
        user_id: int,
        limit: int = 50,
        offset: int = 0,
    ) -> List[AuditReport]:
        items = list(self._items.values())
        items = [a for a in items if a.user_id == user_id]
        # newest first
        items.sort(key=lambda a: a.created_at, reverse=True)
        return items[offset : offset + limit]

    def get_audit_by_id(
        self,
        audit_id: int,
        user_id: Optional[int] = None,
    ) -> Optional[AuditReport]:
        item = self._items.get(audit_id)
        if item is None:
            return None
        if user_id is not None and item.user_id != user_id:
            return None
        return item


_repository: AuditRepository = InMemoryAuditRepository()


def set_audit_repository(repo: AuditRepository) -> None:
    """
    Allow other layers (e.g. DB module, FastAPI) to inject a concrete repo.
    """

    global _repository
    if not isinstance(repo, AuditRepository):
        raise TypeError("repo must implement the AuditRepository protocol")
    _repository = repo
    logger.info("Audit repository has been replaced with a custom implementation.")


def get_audit_repository() -> AuditRepository:
    """
    Returns the current audit repository.
    """

    return _repository


# === Public Service API for other modules ===


def analyze_and_persist_audit(
    qa_chain,
    raw_input: str,
    *,
    user_id: int,
    target_name: str,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> AuditReport:
    """
    High-level operation used by UI / API:

    1. Run heuristic checks.
    2. Run AI-powered deep analysis (RAG).
    3. Aggregate per-function results.
    4. Persist an AuditReport via the configured repository.

    Returns the saved AuditReport instance.

    NOTE:
    - `user_id` will later be provided by the auth layer (Member 2).
    - `target_name` can be contract name or user-defined label from the UI / API.
    """

    logger.info("Starting full audit (heuristics + AI + persistence).")
    t0 = time.perf_counter()

    heuristic_alerts = run_heuristic_checks(raw_input)
    function_results: List[Dict[str, Any]] = []

    def _on_function_analyzed(payload: Dict[str, Any]) -> None:
        function_results.append(payload)

    ai_analysis = analyze_code_with_ai(
        qa_chain,
        raw_input,
        on_function_analyzed=_on_function_analyzed,
    )

    if extra_metadata is None:
        extra_metadata = {}

    # Align with DB contract: heuristic_results is JSON string
    heuristic_results = json.dumps(
        {"alerts": heuristic_alerts},
        ensure_ascii=False,
    )

    vulnerabilities = _extract_vulnerabilities_from_markdown(ai_analysis, raw_input)
    vulnerabilities_count = len(vulnerabilities)
    severity_score = _calculate_severity_score(vulnerabilities)
    analysis_duration = time.perf_counter() - t0

    audit = AuditReport(
        id=0,  # assigned by repository (int PK)
        user_id=user_id,
        contract_code=raw_input,
        contract_name=target_name,
        heuristic_results=heuristic_results,
        ai_analysis=ai_analysis,
        severity_score=severity_score,
        vulnerabilities_count=vulnerabilities_count,
        created_at=datetime.now(timezone.utc),
        analysis_duration=analysis_duration,
        vulnerabilities=vulnerabilities,
        functions=function_results,
        extra_metadata=extra_metadata,
    )

    saved = _repository.create_audit(audit)
    logger.info("Audit successfully persisted with id=%s", saved.id)
    return saved


def list_audits_for_user(
    user_id: int,
    *,
    limit: int = 50,
    offset: int = 0,
) -> List[AuditReport]:
    """
    Convenience wrapper around the repository for UI / API.
    """

    return _repository.list_audits_for_user(user_id=user_id, limit=limit, offset=offset)


def get_audit(
    audit_id: int,
    *,
    user_id: Optional[int] = None,
) -> Optional[AuditReport]:
    """
    Fetch a single audit report by id, optionally scoped to a given user.
    """

    return _repository.get_audit_by_id(audit_id=audit_id, user_id=user_id)


def _extract_vulnerabilities_from_markdown(markdown: str, contract_code: str) -> List[Vulnerability]:
    """
    Best-effort extraction to satisfy the final interface fields:
    - name
    - severity
    - description
    - recommendation
    - line_number (best-effort; 0 if unknown)
    - function_name (best-effort; "Unknown" if not detected)
    """

    vulns: List[Vulnerability] = []

    # Split by function headers produced by src.logic: "## Analysis for: `name`"
    parts = re.split(r"\n## Analysis for: `([^`]+)`\n", "\n" + markdown)
    # parts layout: [prefix, func1_name, func1_body, func2_name, func2_body, ...]
    if len(parts) < 3:
        parts = ["", "Unknown", markdown]

    for i in range(1, len(parts), 2):
        function_name = parts[i] if i < len(parts) else "Unknown"
        body = parts[i + 1] if i + 1 < len(parts) else ""

        # Each vuln block starts with "### Vulnerability:"
        vuln_blocks = re.split(r"\n### Vulnerability:\s*", "\n" + body)
        for block in vuln_blocks[1:]:
            lines = block.strip().splitlines()
            title = lines[0].strip() if lines else "Unknown"

            severity = _extract_field(block, r"\*\*Severity:\*\*\s*(.+)")
            description = _extract_field(block, r"\*\*Description:\*\*\s*(.+)")
            recommendation = _extract_field(block, r"\*\*Recommendation:\*\*\s*(.+)")

            # Best-effort: line_number unknown unless we can find "line" patterns
            line_number = 0
            m = re.search(r"\bline\s+(\d+)\b", block, flags=re.IGNORECASE)
            if m:
                line_number = int(m.group(1))

            # Skip pure "no vulnerabilities" blocks
            if severity.strip().lower() == "none":
                continue

            vulns.append(
                Vulnerability(
                    id=0,  # assigned by repository
                    audit_report_id=0,  # assigned by repository
                    name=title,
                    severity=severity or "Informational",
                    description=description,
                    recommendation=recommendation,
                    line_number=line_number,
                    function_name=function_name,
                )
            )

    return vulns


def _extract_field(text: str, pattern: str) -> str:
    m = re.search(pattern, text)
    if not m:
        return ""
    return m.group(1).strip()


def _calculate_severity_score(vulns: List[Vulnerability]) -> float:
    """
    Convert severities to a 0-10 score.
    Uses the maximum severity present.
    """

    mapping = {
        "critical": 10.0,
        "high": 8.0,
        "medium": 5.0,
        "low": 2.0,
        "informational": 1.0,
        "info": 1.0,
        "none": 0.0,
    }
    max_score = 0.0
    for v in vulns:
        s = mapping.get(v.severity.strip().lower(), 1.0)
        if s > max_score:
            max_score = s
    return max_score

