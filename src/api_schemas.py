from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    """Request body for user registration."""

    username: str = Field(..., description="Unique username for the new user.")
    email: EmailStr = Field(..., description="Email address of the new user.")
    password: str = Field(..., min_length=6, description="Plain-text password to be hashed by the auth module.")


class RegisterResponse(BaseModel):
    """Response body after successful registration."""

    user_id: str = Field(..., description="Unique identifier of the created user.")
    username: str
    email: EmailStr


class LoginRequest(BaseModel):
    """Request body for user login."""

    username: str = Field(..., description="Username or email used for login.")
    password: str = Field(..., description="Plain-text password to be verified by the auth module.")


class LoginResponse(BaseModel):
    """Response body after successful login."""

    access_token: str = Field(..., description="JWT access token for authenticated requests.")
    token_type: str = Field("bearer", description="Type of the returned token.")
    user_id: str = Field(..., description="Identifier of the authenticated user.")


class VulnerabilityFinding(BaseModel):
    """Represents a single vulnerability detected in an audit."""

    id: str
    title: str
    severity: str
    description: str
    recommendation: str
    suggested_code: str


class FunctionAuditResult(BaseModel):
    """Per-function audit result returned from the audit service."""

    id: str
    function_name: str
    source_code: str
    markdown_report: str
    vulnerabilities: List[VulnerabilityFinding] = Field(
        default_factory=list,
        description="List of vulnerabilities detected in this function, if any.",
    )


class AuditReport(BaseModel):
    """
    Full audit report model aligned with docs/INTERFACES.md.

    This is what the API returns to clients for audit-related endpoints.
    """

    id: str
    user_id: Optional[str]
    created_at: datetime
    target_name: Optional[str]
    raw_input: str
    heuristic_alerts: List[str]
    full_markdown_report: str
    functions: List[FunctionAuditResult]
    extra_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata such as network, compiler version, etc.",
    )


class AuditSummary(BaseModel):
    """Lightweight summary item used in audit list responses."""

    id: str
    target_name: Optional[str]
    created_at: datetime


class CreateAuditRequest(BaseModel):
    """Request body for creating a new audit via API."""

    raw_input: str = Field(..., description="Solidity code or security question to be analyzed.")
    target_name: Optional[str] = Field(
        default=None,
        description="Optional label for this audit, such as contract or project name.",
    )
    extra_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata (e.g., network, compiler version).",
    )

