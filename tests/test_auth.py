"""
成员2 & 成员6 - 认证功能测试
包含用户注册、登录、密码管理、Token等测试
"""
import pytest
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
    verify_password_reset_token,
    SessionManager
)


class TestUserRegistration:
    """测试用户注册"""
    
    def test_register_success(self, db_session):
        """
        测试成功注册
        
        TODO: 成员6实现
        """
        user = UserAuth.register_user(
            username="newuser",
            email="new@test.com",
            password="password123"
        )
        
        assert user.username == "newuser"
        assert user.email == "new@test.com"
        assert user.password_hash is not None
        assert user.password_hash != "password123"  # 密码应该被加密
    
    def test_register_duplicate_username(self, db_session, test_user):
        """
        测试重复用户名
        
        TODO: 成员6实现
        - 应该抛出AuthenticationError
        """
        with pytest.raises(AuthenticationError):
            UserAuth.register_user(
                username=test_user.username,
                email="another@test.com",
                password="password123"
            )
    
    def test_register_duplicate_email(self, db_session, test_user):
        """
        测试重复邮箱
        
        TODO: 成员6实现
        """
        with pytest.raises(AuthenticationError):
            UserAuth.register_user(
                username="newuser",
                email=test_user.email,
                password="password123"
            )


class TestUserLogin:
    """测试用户登录"""
    
    def test_login_success(self, db_session, test_user):
        """
        测试成功登录
        
        TODO: 成员6实现
        """
        user = UserAuth.login_user(
            username=test_user.username,
            password="testpass123"
        )
        
        assert user.id == test_user.id
    
    def test_login_with_email(self, db_session, test_user):
        """
        测试用邮箱登录
        
        TODO: 成员6实现
        """
        user = UserAuth.login_user(
            username=test_user.email,
            password="testpass123"
        )
        
        assert user.id == test_user.id
    
    def test_login_wrong_password(self, db_session, test_user):
        """
        测试错误密码
        
        TODO: 成员6实现
        """
        with pytest.raises(AuthenticationError):
            UserAuth.login_user(
                username=test_user.username,
                password="wrongpassword"
            )
    
    def test_login_nonexistent_user(self, db_session):
        """
        测试不存在的用户
        
        TODO: 成员6实现
        """
        with pytest.raises(AuthenticationError):
            UserAuth.login_user(
                username="nonexistent",
                password="password123"
            )


class TestPasswordOperations:
    """测试密码相关操作"""
    
    def test_password_hashing(self):
        """
        测试密码加密
        
        TODO: 成员6实现
        """
        password = "mypassword123"
        hashed, salt = UserAuth.hash_password(password)
        
        assert hashed != password
        assert salt is not None
    
    def test_password_verification(self):
        """
        测试密码验证
        
        TODO: 成员6实现
        """
        password = "mypassword123"
        hashed, _ = UserAuth.hash_password(password)
        
        assert UserAuth.verify_password(password, hashed) is True
        assert UserAuth.verify_password("wrongpassword", hashed) is False
    
    def test_update_password(self, db_session, test_user):
        """
        测试更新密码
        
        TODO: 成员6实现
        """
        success = UserAuth.update_password(
            user_id=test_user.id,
            old_password="testpass123",
            new_password="newpass123"
        )
        
        assert success is True
        
        # 验证新密码可以登录
        user = UserAuth.login_user(test_user.username, "newpass123")
        assert user.id == test_user.id


class TestTokenOperations:
    """测试Token相关操作"""
    
    def test_create_access_token(self):
        """测试创建访问令牌"""
        token = create_access_token(user_id=1, username="testuser")
        assert token is not None
        assert len(token) > 0
    
    def test_create_refresh_token(self):
        """测试创建刷新令牌"""
        token = create_refresh_token(user_id=1)
        assert token is not None
        assert len(token) > 0
    
    def test_verify_access_token(self):
        """测试验证访问令牌"""
        token = create_access_token(user_id=123, username="testuser")
        payload = verify_token(token, token_type="access")
        
        assert payload is not None
        assert payload.get("user_id") == 123
        assert payload.get("username") == "testuser"
        assert payload.get("type") == "access"
    
    def test_verify_refresh_token(self):
        """测试验证刷新令牌"""
        token = create_refresh_token(user_id=123)
        payload = verify_token(token, token_type="refresh")
        
        assert payload is not None
        assert payload.get("user_id") == 123
        assert payload.get("type") == "refresh"
    
    def test_get_user_id_from_token(self):
        """测试从令牌获取用户ID"""
        token = create_access_token(user_id=456)
        user_id = get_user_id_from_token(token)
        
        assert user_id == 456
    
    def test_invalid_token(self):
        """测试无效令牌"""
        payload = verify_token("invalid.token.here")
        assert payload is None
    
    def test_refresh_access_token(self):
        """测试刷新访问令牌"""
        refresh_token = create_refresh_token(user_id=789)
        result = refresh_access_token(refresh_token)
        
        assert result is not None
        new_access_token, new_refresh_token = result
        assert new_access_token is not None
        assert new_refresh_token is not None
        
        # 验证新令牌有效
        payload = verify_token(new_access_token)
        assert payload.get("user_id") == 789


class TestValidation:
    """测试验证功能"""
    
    def test_validate_password_strong(self):
        """测试强密码验证"""
        is_valid, msg = validate_password_strength("StrongPass123")
        assert is_valid is True
    
    def test_validate_password_too_short(self):
        """测试密码太短"""
        is_valid, msg = validate_password_strength("short")
        assert is_valid is False
        assert "8" in msg
    
    def test_validate_password_no_letter(self):
        """测试密码无字母"""
        is_valid, msg = validate_password_strength("12345678")
        assert is_valid is False
        assert "字母" in msg
    
    def test_validate_password_no_number(self):
        """测试密码无数字"""
        is_valid, msg = validate_password_strength("abcdefgh")
        assert is_valid is False
        assert "数字" in msg
    
    def test_validate_email_valid(self):
        """测试有效邮箱"""
        is_valid, msg = validate_email("test@example.com")
        assert is_valid is True
    
    def test_validate_email_invalid(self):
        """测试无效邮箱"""
        is_valid, msg = validate_email("invalid-email")
        assert is_valid is False
    
    def test_validate_username_valid(self):
        """测试有效用户名"""
        is_valid, msg = validate_username("valid_user-123")
        assert is_valid is True
    
    def test_validate_username_too_short(self):
        """测试用户名太短"""
        is_valid, msg = validate_username("ab")
        assert is_valid is False
        assert "3" in msg
    
    def test_validate_username_invalid_chars(self):
        """测试用户名包含无效字符"""
        is_valid, msg = validate_username("user@name")
        assert is_valid is False


class TestPasswordReset:
    """测试密码重置功能"""
    
    def test_generate_reset_token(self):
        """测试生成重置令牌"""
        token = generate_password_reset_token("test@example.com")
        assert token is not None
        assert len(token) > 0
    
    def test_verify_reset_token(self):
        """测试验证重置令牌"""
        email = "test@example.com"
        token = generate_password_reset_token(email)
        
        verified_email = verify_password_reset_token(token)
        assert verified_email == email
    
    def test_invalid_reset_token(self):
        """测试无效重置令牌"""
        result = verify_password_reset_token("invalid.token")
        assert result is None


class TestSessionManager:
    """测试会话管理器"""
    
    def test_create_session(self):
        """测试创建会话"""
        user_data = {
            "id": 1,
            "username": "testuser",
            "email": "test@example.com"
        }
        session = SessionManager.create_session(user_data)
        
        assert session["logged_in"] is True
        assert session["user_id"] == 1
        assert session["username"] == "testuser"
        assert session["access_token"] is not None
        assert session["refresh_token"] is not None
    
    def test_clear_session(self):
        """测试清除会话"""
        session = SessionManager.clear_session()
        
        assert session["logged_in"] is False
        assert session["user_id"] is None
        assert session["access_token"] is None
    
    def test_is_session_valid(self):
        """测试验证会话有效性"""
        user_data = {
            "id": 1,
            "username": "testuser",
            "email": "test@example.com"
        }
        session = SessionManager.create_session(user_data)
        
        assert SessionManager.is_session_valid(session) is True
    
    def test_is_session_invalid(self):
        """测试无效会话"""
        session = {"logged_in": False}
        assert SessionManager.is_session_valid(session) is False


class TestUserManagement:
    """测试用户管理功能"""
    
    def test_get_user_by_id(self, db_session, test_user):
        """测试通过ID获取用户"""
        user = UserAuth.get_user_by_id(test_user.id)
        assert user is not None
        assert user.username == test_user.username
    
    def test_get_user_by_email(self, db_session, test_user):
        """测试通过邮箱获取用户"""
        user = UserAuth.get_user_by_email(test_user.email)
        assert user is not None
        assert user.id == test_user.id
    
    def test_get_user_by_username(self, db_session, test_user):
        """测试通过用户名获取用户"""
        user = UserAuth.get_user_by_username(test_user.username)
        assert user is not None
        assert user.id == test_user.id
    
    def test_check_user_exists(self, db_session, test_user):
        """测试检查用户是否存在"""
        result = UserAuth.check_user_exists(
            username=test_user.username,
            email=test_user.email
        )
        
        assert result["username_exists"] is True
        assert result["email_exists"] is True
        
        result2 = UserAuth.check_user_exists(
            username="nonexistent",
            email="nonexistent@test.com"
        )
        
        assert result2["username_exists"] is False
        assert result2["email_exists"] is False
    
    def test_validate_registration(self, db_session, test_user):
        """测试验证注册信息"""
        # 测试有效信息
        is_valid, errors = UserAuth.validate_registration(
            username="newuser123",
            email="newuser@test.com",
            password="password123"
        )
        assert is_valid is True
        assert len(errors) == 0
        
        # 测试已存在的用户名
        is_valid, errors = UserAuth.validate_registration(
            username=test_user.username,
            email="another@test.com",
            password="password123"
        )
        assert is_valid is False
        assert "用户名已存在" in errors
    
    def test_login_with_token(self, db_session, test_user):
        """测试登录并返回Token"""
        result = UserAuth.login_with_token(
            username=test_user.username,
            password="testpass123"
        )
        
        assert result is not None
        assert result["access_token"] is not None
        assert result["refresh_token"] is not None
        assert result["user"]["id"] == test_user.id
