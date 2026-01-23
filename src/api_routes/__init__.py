from .auth_routes import router as auth_router  # noqa: F401
from .audit_routes import router as audit_router  # noqa: F401
from .stats_routes import router as stats_router  # noqa: F401

__all__ = ["auth_router", "audit_router", "stats_router"]
