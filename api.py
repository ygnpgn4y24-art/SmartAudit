from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api_routes import auth_router, audit_router, stats_router
from src.api_middleware import get_current_user_id  # noqa: F401  # used as shared dependency

app = FastAPI(
    title="Auditor AI API",
    description=(
        "REST API for the Auditor AI smart contract security assistant.\n\n"
        "This service exposes authentication, audit, and statistics endpoints.\n"
        "Many handlers are currently placeholders that return 501 until the\n"
        "authentication, database, and audit service modules are implemented."
    ),
    version="0.1.0",
)

# Basic CORS configuration so that Streamlit or other frontends can call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers under a common /api prefix to match the design docs.
app.include_router(auth_router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(stats_router, prefix="/api")


@app.get("/health", tags=["meta"])
async def health_check() -> dict:
    """Simple health check endpoint."""

    return {"status": "ok"}


if __name__ == "__main__":
    # For local debugging only. In production, use a process manager.
    import uvicorn

    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)

