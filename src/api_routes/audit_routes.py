from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from src.api_middleware import get_current_user_id
from src.api_schemas import AuditReport, AuditSummary, CreateAuditRequest

router = APIRouter(prefix="/audits", tags=["audits"])


@router.post(
    "",
    response_model=AuditReport,
    summary="Create a new audit",
    description=(
        "Triggers a new audit for the provided Solidity code or security question. "
        "Internally this should call `src.audit_service.analyze_and_persist_audit` "
        "once the audit service (成员3) and database (成员1) are ready."
    ),
)
async def create_audit(
    payload: CreateAuditRequest,
    current_user_id: str = Depends(get_current_user_id),
) -> AuditReport:
    """
    Create a new audit for the authenticated user.

    当前实现仅提供 API 形状和文档，尚未接入审计服务。

    未来实现应当：
    - 从依赖 `get_current_user_id` 中获取真实的 `user_id`
    - 调用 `analyze_and_persist_audit(qa_chain, raw_input, user_id, target_name, extra_metadata)`
    - 返回 `AuditReport` 对象（由 Pydantic 模型自动转为 JSON）
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Audit creation is not implemented yet. Waiting for audit_service & database.",
    )


@router.get(
    "",
    response_model=List[AuditSummary],
    summary="List audits for current user",
    description=(
        "Lists audits for the authenticated user with simple pagination. "
        "This will eventually delegate to `list_audits_for_user` from the audit service."
    ),
)
async def list_audits(
    limit: int = 50,
    offset: int = 0,
    current_user_id: str = Depends(get_current_user_id),
) -> List[AuditSummary]:
    """
    List audit summaries for the authenticated user.

    最终实现应当：
    - 调用 `list_audits_for_user(current_user_id, limit, offset)`
    - 将返回的领域对象映射为 `AuditSummary` 列表
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Listing audits is not implemented yet. Waiting for audit_service & database.",
    )


@router.get(
    "/{audit_id}",
    response_model=AuditReport,
    summary="Get a single audit report",
    description=(
        "Returns a full audit report for the given ID, scoped to the authenticated user. "
        "Should call `get_audit(audit_id, user_id=current_user_id)` in the future."
    ),
)
async def get_audit_detail(
    audit_id: str,
    current_user_id: str = Depends(get_current_user_id),
) -> AuditReport:
    """
    Get a full audit report for the given audit ID.

    最终实现需要：
    - 调用 `get_audit(audit_id, user_id=current_user_id)`
    - 若返回 None，则抛出 404
    - 否则将领域对象直接返回，由 Pydantic 进行序列化
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Fetching a single audit is not implemented yet. Waiting for audit_service & database.",
    )

