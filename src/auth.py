"""
成员2 - 用户认证模块
提供注册、登录、密码加密、用户管理等功能
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from src.database import db_manager, User
from src.logger_config import logger
from src.security import (
    create_access_token, 
    create_refresh_token,
    verify_token,
    validate_password_strength,
    validate_email,
    validate_username,
    SessionManager
)


class AuthenticationError(Exception):
    """认证异常"""
    pass


class PermissionError(Exception):
    """权限异常"""
    pass


class UserAuth:
    """用户认证类"""
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> tuple:
        """
        对密码进行哈希加密
        
        Args:
            password: 原始密码
            salt: 盐值（可选）
            
        Returns:
            (hashed_password, salt) 元组
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        return pwd_hash.hex() + ':' + salt, salt
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        验证密码
        
        Args:
            password: 待验证的密码
            hashed_password: 存储的哈希密码
            
        Returns:
            bool: 验证是否成功
        """
        try:
            pwd_hash, salt = hashed_password.split(':')
            new_hash, _ = UserAuth.hash_password(password, salt)
            return new_hash == hashed_password
        except Exception as e:
            logger.error(f"密码验证失败: {e}")
            return False
    
    @staticmethod
    def register_user(username: str, email: str, password: str) -> User:
        """
        注册新用户
        
        Args:
            username: 用户名
            email: 邮箱
            password: 密码
            
        Returns:
            User: 创建的用户对象
            
        Raises:
            AuthenticationError: 用户已存在或其他错误
        """
        session = db_manager.get_session()
        try:
            # 检查用户是否已存在
            existing_user = session.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                if existing_user.username == username:
                    raise AuthenticationError("用户名已存在")
                else:
                    raise AuthenticationError("邮箱已被注册")
            
            # 创建新用户
            hashed_password, _ = UserAuth.hash_password(password)
            new_user = User(
                username=username,
                email=email,
                password_hash=hashed_password
            )
            
            session.add(new_user)
            session.commit()
            session.refresh(new_user)
            
            logger.info(f"新用户注册成功: {username}")
            return new_user
            
        except AuthenticationError:
            session.rollback()
            raise
        except Exception as e:
            session.rollback()
            logger.error(f"用户注册失败: {e}", exc_info=True)
            raise AuthenticationError(f"注册失败: {str(e)}")
        finally:
            db_manager.close_session(session)
    
    @staticmethod
    def login_user(username: str, password: str) -> User:
        """
        用户登录
        
        Args:
            username: 用户名或邮箱
            password: 密码
            
        Returns:
            User: 用户对象
            
        Raises:
            AuthenticationError: 登录失败
        """
        session = db_manager.get_session()
        try:
            # 支持用户名或邮箱登录
            user = session.query(User).filter(
                (User.username == username) | (User.email == username)
            ).first()
            
            if not user:
                raise AuthenticationError("用户不存在")
            
            if not user.is_active:
                raise AuthenticationError("账户已被禁用")
            
            if not UserAuth.verify_password(password, user.password_hash):
                raise AuthenticationError("密码错误")
            
            logger.info(f"用户登录成功: {user.username}")
            return user
            
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"登录失败: {e}", exc_info=True)
            raise AuthenticationError(f"登录失败: {str(e)}")
        finally:
            db_manager.close_session(session)
    
    @staticmethod
    def get_user_by_id(user_id: int) -> User:
        """
        根据ID获取用户
        
        Args:
            user_id: 用户ID
            
        Returns:
            User: 用户对象或None
        """
        session = db_manager.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            return user
        finally:
            db_manager.close_session(session)
    
    @staticmethod
    def update_password(user_id: int, old_password: str, new_password: str) -> bool:
        """
        更新用户密码
        
        Args:
            user_id: 用户ID
            old_password: 旧密码
            new_password: 新密码
            
        Returns:
            bool: 是否成功
        """
        session = db_manager.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                raise AuthenticationError("用户不存在")
            
            if not UserAuth.verify_password(old_password, user.password_hash):
                raise AuthenticationError("旧密码错误")
            
            new_hash, _ = UserAuth.hash_password(new_password)
            user.password_hash = new_hash
            session.commit()
            
            logger.info(f"用户 {user.username} 更新密码成功")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"密码更新失败: {e}", exc_info=True)
            return False
        finally:
            db_manager.close_session(session)

    @staticmethod
    def reset_password(email: str, new_password: str) -> bool:
        """
        重置用户密码（通过邮箱）
        
        Args:
            email: 用户邮箱
            new_password: 新密码
            
        Returns:
            bool: 是否成功
        """
        session = db_manager.get_session()
        try:
            user = session.query(User).filter(User.email == email).first()
            if not user:
                raise AuthenticationError("邮箱未注册")
            
            # 验证新密码强度
            is_valid, msg = validate_password_strength(new_password)
            if not is_valid:
                raise AuthenticationError(msg)
            
            new_hash, _ = UserAuth.hash_password(new_password)
            user.password_hash = new_hash
            session.commit()
            
            logger.info(f"用户 {user.username} 密码重置成功")
            return True
            
        except AuthenticationError:
            raise
        except Exception as e:
            session.rollback()
            logger.error(f"密码重置失败: {e}", exc_info=True)
            return False
        finally:
            db_manager.close_session(session)

    @staticmethod
    def deactivate_user(user_id: int) -> bool:
        """
        停用用户账户
        
        Args:
            user_id: 用户ID
            
        Returns:
            bool: 是否成功
        """
        session = db_manager.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                raise AuthenticationError("用户不存在")
            
            user.is_active = False
            session.commit()
            
            logger.info(f"用户 {user.username} 已停用")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"停用用户失败: {e}", exc_info=True)
            return False
        finally:
            db_manager.close_session(session)

    @staticmethod
    def activate_user(user_id: int) -> bool:
        """
        激活用户账户
        
        Args:
            user_id: 用户ID
            
        Returns:
            bool: 是否成功
        """
        session = db_manager.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                raise AuthenticationError("用户不存在")
            
            user.is_active = True
            session.commit()
            
            logger.info(f"用户 {user.username} 已激活")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"激活用户失败: {e}", exc_info=True)
            return False
        finally:
            db_manager.close_session(session)

    @staticmethod
    def get_all_users(include_inactive: bool = False) -> List[User]:
        """
        获取所有用户
        
        Args:
            include_inactive: 是否包含已停用的用户
            
        Returns:
            List[User]: 用户列表
        """
        session = db_manager.get_session()
        try:
            query = session.query(User)
            if not include_inactive:
                query = query.filter(User.is_active == True)
            return query.all()
        finally:
            db_manager.close_session(session)

    @staticmethod
    def get_user_by_email(email: str) -> Optional[User]:
        """
        根据邮箱获取用户
        
        Args:
            email: 邮箱地址
            
        Returns:
            Optional[User]: 用户对象或None
        """
        session = db_manager.get_session()
        try:
            user = session.query(User).filter(User.email == email).first()
            return user
        finally:
            db_manager.close_session(session)

    @staticmethod
    def get_user_by_username(username: str) -> Optional[User]:
        """
        根据用户名获取用户
        
        Args:
            username: 用户名
            
        Returns:
            Optional[User]: 用户对象或None
        """
        session = db_manager.get_session()
        try:
            user = session.query(User).filter(User.username == username).first()
            return user
        finally:
            db_manager.close_session(session)

    @staticmethod
    def update_user_info(user_id: int, **kwargs) -> bool:
        """
        更新用户信息
        
        Args:
            user_id: 用户ID
            **kwargs: 要更新的字段（username, email等）
            
        Returns:
            bool: 是否成功
        """
        session = db_manager.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                raise AuthenticationError("用户不存在")
            
            # 验证并更新字段
            if 'username' in kwargs:
                is_valid, msg = validate_username(kwargs['username'])
                if not is_valid:
                    raise AuthenticationError(msg)
                # 检查用户名是否已存在
                existing = session.query(User).filter(
                    User.username == kwargs['username'],
                    User.id != user_id
                ).first()
                if existing:
                    raise AuthenticationError("用户名已存在")
                user.username = kwargs['username']
            
            if 'email' in kwargs:
                is_valid, msg = validate_email(kwargs['email'])
                if not is_valid:
                    raise AuthenticationError(msg)
                # 检查邮箱是否已存在
                existing = session.query(User).filter(
                    User.email == kwargs['email'],
                    User.id != user_id
                ).first()
                if existing:
                    raise AuthenticationError("邮箱已被注册")
                user.email = kwargs['email']
            
            session.commit()
            logger.info(f"用户 {user.username} 信息更新成功")
            return True
            
        except AuthenticationError:
            session.rollback()
            raise
        except Exception as e:
            session.rollback()
            logger.error(f"更新用户信息失败: {e}", exc_info=True)
            return False
        finally:
            db_manager.close_session(session)

    @staticmethod
    def check_user_exists(username: str = None, email: str = None) -> Dict[str, bool]:
        """
        检查用户名或邮箱是否已存在
        
        Args:
            username: 用户名
            email: 邮箱
            
        Returns:
            Dict[str, bool]: {'username_exists': bool, 'email_exists': bool}
        """
        session = db_manager.get_session()
        try:
            result = {'username_exists': False, 'email_exists': False}
            
            if username:
                user = session.query(User).filter(User.username == username).first()
                result['username_exists'] = user is not None
            
            if email:
                user = session.query(User).filter(User.email == email).first()
                result['email_exists'] = user is not None
            
            return result
        finally:
            db_manager.close_session(session)

    @staticmethod
    def validate_registration(username: str, email: str, password: str) -> tuple:
        """
        验证注册信息
        
        Args:
            username: 用户名
            email: 邮箱
            password: 密码
            
        Returns:
            tuple: (is_valid: bool, errors: list)
        """
        errors = []
        
        # 验证用户名
        is_valid, msg = validate_username(username)
        if not is_valid:
            errors.append(msg)
        
        # 验证邮箱
        is_valid, msg = validate_email(email)
        if not is_valid:
            errors.append(msg)
        
        # 验证密码
        is_valid, msg = validate_password_strength(password)
        if not is_valid:
            errors.append(msg)
        
        # 检查用户名和邮箱是否已存在
        exists = UserAuth.check_user_exists(username, email)
        if exists['username_exists']:
            errors.append("用户名已存在")
        if exists['email_exists']:
            errors.append("邮箱已被注册")
        
        return len(errors) == 0, errors

    @staticmethod
    def login_with_token(username: str, password: str) -> Dict[str, Any]:
        """
        登录并返回Token
        
        Args:
            username: 用户名或邮箱
            password: 密码
            
        Returns:
            Dict: 包含用户信息和Token的字典
        """
        user = UserAuth.login_user(username, password)
        
        # 创建Token
        access_token = create_access_token(user.id, user.username)
        refresh_token = create_refresh_token(user.id)
        
        return {
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'created_at': user.created_at.isoformat() if user.created_at else None
            },
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer'
        }

    @staticmethod
    def get_current_user_from_token(token: str) -> Optional[User]:
        """
        从Token获取当前用户
        
        Args:
            token: JWT访问令牌
            
        Returns:
            Optional[User]: 用户对象或None
        """
        payload = verify_token(token)
        if not payload:
            return None
        
        user_id = payload.get('user_id')
        if not user_id:
            return None
        
        return UserAuth.get_user_by_id(user_id)


# ==================== 认证装饰器（用于Streamlit） ====================

def require_login(func):
    """
    登录验证装饰器
    用于需要登录才能访问的页面
    """
    import streamlit as st
    from functools import wraps
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not st.session_state.get('logged_in', False):
            st.warning("⚠️ 请先登录")
            st.stop()
        return func(*args, **kwargs)
    return wrapper


def get_current_user():
    """
    获取当前登录用户（从Streamlit session）
    
    Returns:
        Optional[User]: 当前用户或None
    """
    import streamlit as st
    
    if not st.session_state.get('logged_in', False):
        return None
    
    user_id = st.session_state.get('user_id')
    if not user_id:
        return None
    
    return UserAuth.get_user_by_id(user_id)
