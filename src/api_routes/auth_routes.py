"""
成员2 & 成员5 - 认证相关API路由
提供用户注册、登录、Token管理等RESTful API
"""
from fastapi import APIRouter, HTTPException, status, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from src.auth import UserAuth, AuthenticationError
from src.security import (
    create_access_token, 
    create_refresh_token,
    verify_token,
    get_user_id_from_token,
    refresh_access_token,
    validate_password_strength,
    validate_email,
    validate_username,
    generate_password_reset_token,
    verify_password_reset_token
)
from src.logger_config import logger

router = APIRouter()
security = HTTPBearer()


# ==================== Pydantic模型 ====================

class UserRegisterRequest(BaseModel):
    """用户注册请求"""
    username: str = Field(..., min_length=3, max_length=50, description="用户名")
    email: EmailStr = Field(..., description="邮箱")
    password: str = Field(..., min_length=8, max_length=128, description="密码")
    
    @validator('username')
    def validate_username(cls, v):
        is_valid, msg = validate_username(v)
        if not is_valid:
            raise ValueError(msg)
        return v
    
    @validator('password')
    def validate_password(cls, v):
        is_valid, msg = validate_password_strength(v)
        if not is_valid:
            raise ValueError(msg)
        return v


class UserLoginRequest(BaseModel):
    """用户登录请求"""
    username: str = Field(..., description="用户名或邮箱")
    password: str = Field(..., description="密码")


class TokenResponse(BaseModel):
    """Token响应"""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int = 86400  # 24小时
    user_id: int
    username: str


class UserInfoResponse(BaseModel):
    """用户信息响应"""
    id: int
    username: str
    email: str
    created_at: Optional[str] = None
    is_active: bool = True


class RefreshTokenRequest(BaseModel):
    """刷新Token请求"""
    refresh_token: str


class PasswordUpdateRequest(BaseModel):
    """密码更新请求"""
    old_password: str
    new_password: str = Field(..., min_length=8, max_length=128)
    
    @validator('new_password')
    def validate_new_password(cls, v):
        is_valid, msg = validate_password_strength(v)
        if not is_valid:
            raise ValueError(msg)
        return v


class PasswordResetRequest(BaseModel):
    """密码重置请求"""
    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    """密码重置确认请求"""
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)


class UserUpdateRequest(BaseModel):
    """用户信息更新请求"""
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None


class MessageResponse(BaseModel):
    """通用消息响应"""
    message: str
    success: bool = True


# ==================== 依赖函数 ====================

async def get_current_user_id(credentials: HTTPAuthorizationCredentials = Depends(security)) -> int:
    """
    从Token获取当前用户ID（依赖注入）
    """
    token = credentials.credentials
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的访问令牌",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return user_id


async def get_current_user(user_id: int = Depends(get_current_user_id)):
    """
    获取当前用户对象（依赖注入）
    """
    user = UserAuth.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="用户账户已被禁用"
        )
    
    return user


# ==================== API端点 ====================

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(request: UserRegisterRequest):
    """
    用户注册
    
    - **username**: 用户名（3-50字符，只能包含字母、数字、下划线、连字符）
    - **email**: 有效邮箱地址
    - **password**: 密码（至少8字符，包含字母和数字）
    """
    try:
        user = UserAuth.register_user(
            username=request.username,
            email=request.email,
            password=request.password
        )
        
        # 生成Token
        access_token = create_access_token(user.id, user.username)
        refresh_token = create_refresh_token(user.id)
        
        logger.info(f"API注册成功: {user.username}")
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            user_id=user.id,
            username=user.username
        )
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"API注册失败: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="注册失败，请稍后重试"
        )


@router.post("/login", response_model=TokenResponse)
async def login(request: UserLoginRequest):
    """
    用户登录
    
    - **username**: 用户名或邮箱
    - **password**: 密码
    """
    try:
        user = UserAuth.login_user(
            username=request.username,
            password=request.password
        )
        
        access_token = create_access_token(user.id, user.username)
        refresh_token = create_refresh_token(user.id)
        
        logger.info(f"API登录成功: {user.username}")
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            user_id=user.id,
            username=user.username
        )
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as e:
        logger.error(f"API登录失败: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="登录失败，请稍后重试"
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshTokenRequest):
    """
    刷新访问令牌
    
    - **refresh_token**: 刷新令牌
    """
    result = refresh_access_token(request.refresh_token)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="刷新令牌无效或已过期",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    new_access_token, new_refresh_token = result
    
    # 从刷新令牌获取用户信息
    payload = verify_token(request.refresh_token, token_type="refresh")
    user_id = payload.get("user_id")
    user = UserAuth.get_user_by_id(user_id)
    
    logger.info(f"Token刷新成功: 用户ID {user_id}")
    
    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        user_id=user_id,
        username=user.username if user else "Unknown"
    )


@router.get("/me", response_model=UserInfoResponse)
async def get_me(user = Depends(get_current_user)):
    """
    获取当前用户信息
    
    需要认证：Bearer Token
    """
    return UserInfoResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        created_at=user.created_at.isoformat() if user.created_at else None,
        is_active=user.is_active
    )


@router.put("/me", response_model=UserInfoResponse)
async def update_me(request: UserUpdateRequest, user = Depends(get_current_user)):
    """
    更新当前用户信息
    
    需要认证：Bearer Token
    """
    update_data = {}
    
    if request.username:
        update_data['username'] = request.username
    if request.email:
        update_data['email'] = request.email
    
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="没有提供要更新的字段"
        )
    
    try:
        success = UserAuth.update_user_info(user.id, **update_data)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="更新失败"
            )
        
        # 重新获取用户信息
        updated_user = UserAuth.get_user_by_id(user.id)
        
        logger.info(f"用户信息更新成功: {user.username}")
        
        return UserInfoResponse(
            id=updated_user.id,
            username=updated_user.username,
            email=updated_user.email,
            created_at=updated_user.created_at.isoformat() if updated_user.created_at else None,
            is_active=updated_user.is_active
        )
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/password/update", response_model=MessageResponse)
async def update_password(request: PasswordUpdateRequest, user = Depends(get_current_user)):
    """
    更新密码
    
    需要认证：Bearer Token
    """
    try:
        success = UserAuth.update_password(
            user_id=user.id,
            old_password=request.old_password,
            new_password=request.new_password
        )
        
        if success:
            logger.info(f"密码更新成功: {user.username}")
            return MessageResponse(message="密码更新成功")
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="密码更新失败"
            )
            
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/password/reset-request", response_model=MessageResponse)
async def request_password_reset(request: PasswordResetRequest):
    """
    请求密码重置（发送重置邮件）
    
    注意：出于安全考虑，无论邮箱是否存在都会返回成功消息
    """
    user = UserAuth.get_user_by_email(request.email)
    
    if user:
        # 生成重置令牌
        reset_token = generate_password_reset_token(request.email)
        # TODO: 发送重置邮件
        logger.info(f"密码重置请求: {request.email}")
    
    return MessageResponse(message="如果该邮箱已注册，您将收到密码重置邮件")


@router.post("/password/reset-confirm", response_model=MessageResponse)
async def confirm_password_reset(request: PasswordResetConfirmRequest):
    """
    确认密码重置
    """
    email = verify_password_reset_token(request.token)
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="重置令牌无效或已过期"
        )
    
    try:
        success = UserAuth.reset_password(email, request.new_password)
        
        if success:
            logger.info(f"密码重置成功: {email}")
            return MessageResponse(message="密码重置成功，请使用新密码登录")
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="密码重置失败"
            )
            
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/logout", response_model=MessageResponse)
async def logout(user_id: int = Depends(get_current_user_id)):
    """
    用户登出
    
    注意：JWT是无状态的，实际登出需要在客户端删除Token
    如需实现Token撤销，需要使用Token黑名单（Redis）
    """
    logger.info(f"用户登出: ID {user_id}")
    return MessageResponse(message="登出成功")


@router.get("/verify", response_model=MessageResponse)
async def verify_auth(user_id: int = Depends(get_current_user_id)):
    """
    验证Token是否有效
    
    需要认证：Bearer Token
    """
    return MessageResponse(message="Token有效", success=True)


@router.get("/check-username/{username}")
async def check_username(username: str):
    """
    检查用户名是否可用
    """
    exists = UserAuth.check_user_exists(username=username)
    return {
        "username": username,
        "available": not exists.get('username_exists', False)
    }


@router.get("/check-email/{email}")
async def check_email(email: str):
    """
    检查邮箱是否可用
    """
    # 验证邮箱格式
    is_valid, _ = validate_email(email)
    if not is_valid:
        return {
            "email": email,
            "available": False,
            "reason": "邮箱格式不正确"
        }
    
    exists = UserAuth.check_user_exists(email=email)
    return {
        "email": email,
        "available": not exists.get('email_exists', False)
    }
