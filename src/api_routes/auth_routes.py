from fastapi import APIRouter, HTTPException, status

from src.api_schemas import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Creates a new user account. Password hashing and validation "
    "will be handled by the authentication module (成员2).",
)
async def register_user(payload: RegisterRequest) -> RegisterResponse:
    """
    Register a new user.

    当前实现只是一个占位符，用于暴露 API 形状和文档。
    一旦 `src.auth.UserAuth` 完成后，这里应当：

    - 调用 `UserAuth.register_user(username, email, password)`
    - 捕获并转换认证模块抛出的业务异常为 HTTP 错误码
    - 返回真实的用户信息
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="User registration is not implemented yet. Waiting for auth module.",
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Login and obtain access token",
    description="Authenticates a user and returns a JWT access token. "
    "The actual credential verification and token creation will be delegated "
    "to the authentication and security modules (成员2).",
)
async def login_user(payload: LoginRequest) -> LoginResponse:
    """
    Login a user and return a bearer token.

    一旦认证与安全模块准备好，这里应当：

    - 调用 `UserAuth.login_user(username, password)` 获取用户对象
    - 调用 `create_access_token(user_id=user.id)` 生成 JWT
    - 返回 `LoginResponse`，其中 `user_id` 与 Token 中保持一致
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="User login is not implemented yet. Waiting for auth & security modules.",
    )

