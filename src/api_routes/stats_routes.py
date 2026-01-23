from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status

from src.api_middleware import get_current_user_id

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get(
    "/summary",
    summary="Get audit statistics summary",
    description=(
        "Returns high-level statistics for the authenticated user's audits, such as "
        "total count, recent activity, and severity distribution. "
        "The exact shape of the payload can be refined once members 1 and 3 "
        "finalize the database schema and audit service."
    ),
)
async def get_stats_summary(
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """
    Get high-level statistics for the current user's audits.

    目前返回 501 作为占位。未来可以根据需求返回，例如：
    {
        "total_audits": 12,
        "last_7_days": 3,
        "severity_distribution": {
            "Critical": 1,
            "High": 2,
            "Medium": 4,
            "Low": 3,
            "Informational": 2,
        }
    }
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Statistics endpoints are not implemented yet. Waiting for DB schema & audit_service.",
    )

