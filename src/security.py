"""
成员2 - 安全工具模块

提供JWT Token、密码加密、权限控制等安全功能
"""
import jwt
import secrets
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from functools import wraps
from config import JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRATION_HOURS
from src.logger_config import logger


# ==================== Token管理 ====================

def create_access_token(user_id: int, username: str = None, expires_delta: Optional[timedelta] = None) -> str:
    """
    创建JWT访问令牌
    
    Args:
        user_id: 用户ID
        username: 用户名（可选，用于在token中包含更多信息）
        expires_delta: 过期时间（可选）
        
    Returns:
        str: JWT令牌
    """
    if expires_delta is None:
        expires_delta = timedelta(hours=JWT_EXPIRATION_HOURS)
    
    expire = datetime.utcnow() + expires_delta
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    logger.info(f"为用户 {user_id} 创建访问令牌")
    return token


def create_refresh_token(user_id: int, expires_delta: Optional[timedelta] = None) -> str:
    """
    创建刷新令牌（用于获取新的访问令牌）
    
    Args:
        user_id: 用户ID
        expires_delta: 过期时间（默认7天）
        
    Returns:
        str: 刷新令牌
    """
    if expires_delta is None:
        expires_delta = timedelta(days=7)
    
    expire = datetime.utcnow() + expires_delta
    payload = {
        "user_id": user_id,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh",
        "jti": secrets.token_hex(16)  # 唯一标识符，可用于令牌撤销
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    logger.info(f"为用户 {user_id} 创建刷新令牌")
    return token


def verify_token(token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
    """
    验证JWT令牌并返回payload
    
    Args:
        token: JWT令牌
        token_type: 令牌类型 ("access" 或 "refresh")
        
    Returns:
        Optional[Dict]: payload字典，验证失败返回None
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        # 验证令牌类型
        if payload.get("type") != token_type:
            logger.warning(f"令牌类型不匹配: 期望 {token_type}, 实际 {payload.get('type')}")
            return None
        
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token已过期")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"无效的Token: {e}")
        return None


def get_user_id_from_token(token: str) -> Optional[int]:
    """
    从令牌中获取用户ID
    
    Args:
        token: JWT令牌
        
    Returns:
        Optional[int]: 用户ID，验证失败返回None
    """
    payload = verify_token(token)
    if payload:
        return payload.get("user_id")
    return None


def refresh_access_token(refresh_token: str) -> Optional[Tuple[str, str]]:
    """
    使用刷新令牌获取新的访问令牌
    
    Args:
        refresh_token: 刷新令牌
        
    Returns:
        Optional[Tuple[str, str]]: (新访问令牌, 新刷新令牌)，失败返回None
    """
    payload = verify_token(refresh_token, token_type="refresh")
    if not payload:
        return None
    
    user_id = payload.get("user_id")
    new_access_token = create_access_token(user_id)
    new_refresh_token = create_refresh_token(user_id)
    
    logger.info(f"用户 {user_id} 刷新令牌成功")
    return new_access_token, new_refresh_token


# ==================== 密码重置 ====================

def generate_password_reset_token(email: str, expires_minutes: int = 30) -> str:
    """
    生成密码重置令牌
    
    Args:
        email: 用户邮箱
        expires_minutes: 过期时间（分钟）
        
    Returns:
        str: 密码重置令牌
    """
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    payload = {
        "email": email,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "password_reset",
        "jti": secrets.token_hex(16)
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    logger.info(f"为邮箱 {email} 生成密码重置令牌")
    return token


def verify_password_reset_token(token: str) -> Optional[str]:
    """
    验证密码重置令牌
    
    Args:
        token: 密码重置令牌
        
    Returns:
        Optional[str]: 邮箱地址，验证失败返回None
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        if payload.get("type") != "password_reset":
            logger.warning("无效的密码重置令牌类型")
            return None
        
        return payload.get("email")
    except jwt.ExpiredSignatureError:
        logger.warning("密码重置令牌已过期")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"无效的密码重置令牌: {e}")
        return None


# ==================== 密码验证 ====================

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    验证密码强度
    
    Args:
        password: 密码
        
    Returns:
        Tuple[bool, str]: (是否有效, 错误信息)
    """
    if len(password) < 8:
        return False, "密码长度至少为8个字符"
    
    if len(password) > 128:
        return False, "密码长度不能超过128个字符"
    
    if not re.search(r'[A-Za-z]', password):
        return False, "密码必须包含至少一个字母"
    
    if not re.search(r'\d', password):
        return False, "密码必须包含至少一个数字"
    
    # 可选：检查特殊字符
    # if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
    #     return False, "密码必须包含至少一个特殊字符"
    
    return True, "密码强度符合要求"


def validate_email(email: str) -> Tuple[bool, str]:
    """
    验证邮箱格式
    
    Args:
        email: 邮箱地址
        
    Returns:
        Tuple[bool, str]: (是否有效, 错误信息)
    """
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "邮箱格式不正确"
    
    if len(email) > 100:
        return False, "邮箱长度不能超过100个字符"
    
    return True, "邮箱格式正确"


def validate_username(username: str) -> Tuple[bool, str]:
    """
    验证用户名格式
    
    Args:
        username: 用户名
        
    Returns:
        Tuple[bool, str]: (是否有效, 错误信息)
    """
    if len(username) < 3:
        return False, "用户名长度至少为3个字符"
    
    if len(username) > 50:
        return False, "用户名长度不能超过50个字符"
    
    # 用户名只能包含字母、数字、下划线和连字符
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "用户名只能包含字母、数字、下划线和连字符"
    
    return True, "用户名格式正确"


# ==================== 权限控制 ====================

class Permission:
    """权限常量"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


class Role:
    """角色常量"""
    USER = "user"
    ADMIN = "admin"
    AUDITOR = "auditor"


# 角色权限映射
ROLE_PERMISSIONS = {
    Role.USER: [Permission.READ, Permission.WRITE],
    Role.AUDITOR: [Permission.READ, Permission.WRITE, Permission.DELETE],
    Role.ADMIN: [Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN],
}


def check_permission(user_role: str, required_permission: str) -> bool:
    """
    检查用户是否具有指定权限
    
    Args:
        user_role: 用户角色
        required_permission: 所需权限
        
    Returns:
        bool: 是否具有权限
    """
    permissions = ROLE_PERMISSIONS.get(user_role, [])
    return required_permission in permissions


def require_permission(permission: str):
    """
    权限装饰器（用于API路由）
    
    Args:
        permission: 所需权限
        
    Returns:
        装饰器函数
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 这里需要从请求上下文中获取用户角色
            # 在FastAPI中可以通过依赖注入实现
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ==================== 会话管理 ====================

class SessionManager:
    """会话管理器（用于Streamlit）"""
    
    @staticmethod
    def create_session(user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        创建会话数据
        
        Args:
            user_data: 用户数据（包含id, username等）
            
        Returns:
            Dict: 会话数据
        """
        return {
            "logged_in": True,
            "user_id": user_data.get("id"),
            "username": user_data.get("username"),
            "email": user_data.get("email"),
            "role": user_data.get("role", Role.USER),
            "login_time": datetime.utcnow().isoformat(),
            "access_token": create_access_token(
                user_data.get("id"), 
                user_data.get("username")
            ),
            "refresh_token": create_refresh_token(user_data.get("id"))
        }
    
    @staticmethod
    def clear_session() -> Dict[str, Any]:
        """
        清除会话数据
        
        Returns:
            Dict: 空会话数据
        """
        return {
            "logged_in": False,
            "user_id": None,
            "username": None,
            "email": None,
            "role": None,
            "login_time": None,
            "access_token": None,
            "refresh_token": None
        }
    
    @staticmethod
    def is_session_valid(session_data: Dict[str, Any]) -> bool:
        """
        检查会话是否有效
        
        Args:
            session_data: 会话数据
            
        Returns:
            bool: 会话是否有效
        """
        if not session_data.get("logged_in"):
            return False
        
        access_token = session_data.get("access_token")
        if not access_token:
            return False
        
        # 验证访问令牌
        payload = verify_token(access_token)
        return payload is not None


# ==================== 安全工具函数 ====================

def generate_secure_token(length: int = 32) -> str:
    """
    生成安全随机令牌
    
    Args:
        length: 令牌长度（字节数）
        
    Returns:
        str: 十六进制令牌
    """
    return secrets.token_hex(length)


def sanitize_input(input_str: str) -> str:
    """
    清理用户输入，防止XSS攻击
    
    Args:
        input_str: 原始输入
        
    Returns:
        str: 清理后的输入
    """
    if not input_str:
        return ""
    
    # 移除或转义危险字符
    dangerous_chars = ['<', '>', '"', "'", '&', '\\']
    result = input_str
    for char in dangerous_chars:
        result = result.replace(char, '')
    
    return result.strip()


def mask_email(email: str) -> str:
    """
    掩码邮箱地址（用于显示）
    
    Args:
        email: 原始邮箱
        
    Returns:
        str: 掩码后的邮箱
    """
    if not email or '@' not in email:
        return email
    
    local, domain = email.split('@')
    if len(local) <= 2:
        masked_local = local[0] + '*'
    else:
        masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
    
    return f"{masked_local}@{domain}"


def rate_limit_check(user_id: int, action: str, max_attempts: int = 5, window_minutes: int = 15) -> Tuple[bool, str]:
    """
    简单的速率限制检查（需要配合Redis等存储实现完整功能）
    
    Args:
        user_id: 用户ID
        action: 操作类型
        max_attempts: 最大尝试次数
        window_minutes: 时间窗口（分钟）
        
    Returns:
        Tuple[bool, str]: (是否允许, 消息)
    
    Note:
        这是一个简化实现，实际生产环境应使用Redis等存储
    """
    # TODO: 实现完整的速率限制逻辑（需要Redis）
    return True, "允许操作"
