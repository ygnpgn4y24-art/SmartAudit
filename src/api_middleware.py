from typing import Optional

from fastapi import Header, HTTPException, status


def get_current_user_id(authorization: Optional[str] = Header(default=None)) -> str:
    """
    Dependency that extracts the current user id from the Authorization header.

    This is intentionally a minimal placeholder implementation so that
    API routes can be wired up before the authentication module is ready.

    Expected future integration (成员2 / 认证模块):
    - Parse the `Authorization` header as `Bearer <token>`.
    - Call `src.security.verify_token(token)` to validate and decode the JWT.
    - Return the real `user_id` embedded in the token.

    Until that is implemented, this function:
    - Requires that the Authorization header is present.
    - Does NOT verify the token content.
    - Returns a demo user id string.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Missing Authorization header.",
        )

    # TODO: replace this with real JWT parsing and verification.
    # Example (to be implemented once src.security is available):
    #   scheme, _, token = authorization.partition(" ")
+    #   if scheme.lower() != "bearer" or not token:
    #       raise HTTPException(status_code=401, detail="Invalid authorization header.")
    #   user_id = verify_token(token)
    #   if user_id is None:
    #       raise HTTPException(status_code=401, detail="Invalid or expired token.")
    #   return str(user_id)

    return "demo-user"

