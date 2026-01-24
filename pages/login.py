"""
成员2 - Streamlit登录页面
提供用户登录界面和认证功能
"""
import streamlit as st
from src.auth import UserAuth, AuthenticationError
from src.security import (
    SessionManager, 
    validate_email, 
    mask_email,
    generate_password_reset_token,
    verify_password_reset_token
)
from src.logger_config import logger


def init_session_state():
    """初始化session状态"""
    defaults = {
        'logged_in': False,
        'user_id': None,
        'username': None,
        'email': None,
        'access_token': None,
        'refresh_token': None,
        'login_attempts': 0,
        'show_password_reset': False,
        'reset_token_sent': False
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def show_login_form():
    """显示登录表单"""
    st.subheader("👤 用户登录")
    
    with st.form("login_form", clear_on_submit=False):
        username = st.text_input(
            "用户名或邮箱", 
            placeholder="请输入用户名或邮箱",
            help="支持使用用户名或注册邮箱登录"
        )
        password = st.text_input(
            "密码", 
            type="password", 
            placeholder="请输入密码"
        )
        
        col1, col2 = st.columns([1, 1])
        with col1:
            remember_me = st.checkbox("记住我", value=False)
        with col2:
            submit = st.form_submit_button("🔑 登录", use_container_width=True)
        
        if submit:
            handle_login(username, password, remember_me)
    
    # 忘记密码链接
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔒 忘记密码？", use_container_width=True):
            st.session_state['show_password_reset'] = True
            st.rerun()
    with col2:
        if st.button("📝 注册新账户", use_container_width=True):
            st.session_state['page'] = 'register'
            st.rerun()


def handle_login(username: str, password: str, remember_me: bool = False):
    """处理登录逻辑"""
    # 输入验证
    if not username or not password:
        st.error("❌ 请填写用户名和密码")
        return
    
    # 检查登录尝试次数
    if st.session_state.get('login_attempts', 0) >= 5:
        st.error("⚠️ 登录尝试次数过多，请稍后再试")
        logger.warning(f"登录尝试次数过多: {username}")
        return
    
    try:
        # 调用登录接口
        user = UserAuth.login_user(username, password)
        
        # 创建会话
        session_data = SessionManager.create_session({
            'id': user.id,
            'username': user.username,
            'email': user.email
        })
        
        # 保存到session_state
        for key, value in session_data.items():
            st.session_state[key] = value
        
        # 重置登录尝试次数
        st.session_state['login_attempts'] = 0
        
        st.success(f"✅ 欢迎回来，{user.username}！")
        logger.info(f"用户 {user.username} 登录成功")
        
        # 短暂延迟后重定向
        st.balloons()
        st.rerun()
        
    except AuthenticationError as e:
        st.session_state['login_attempts'] = st.session_state.get('login_attempts', 0) + 1
        st.error(f"❌ 登录失败: {e}")
        logger.warning(f"登录失败 - 用户: {username}, 原因: {e}")
    except Exception as e:
        st.error("❌ 系统错误，请稍后重试")
        logger.error(f"登录异常: {e}", exc_info=True)


def show_password_reset_form():
    """显示密码重置表单"""
    st.subheader("🔒 重置密码")
    
    if not st.session_state.get('reset_token_sent', False):
        # 步骤1: 输入邮箱
        with st.form("reset_email_form"):
            email = st.text_input(
                "注册邮箱", 
                placeholder="请输入您的注册邮箱"
            )
            submit = st.form_submit_button("📧 发送重置链接", use_container_width=True)
            
            if submit:
                if not email:
                    st.error("❌ 请输入邮箱地址")
                else:
                    is_valid, msg = validate_email(email)
                    if not is_valid:
                        st.error(f"❌ {msg}")
                    else:
                        # 检查邮箱是否存在
                        user = UserAuth.get_user_by_email(email)
                        if user:
                            # 生成重置令牌
                            reset_token = generate_password_reset_token(email)
                            st.session_state['reset_email'] = email
                            st.session_state['reset_token'] = reset_token
                            st.session_state['reset_token_sent'] = True
                            
                            # 这里应该发送邮件，但为演示目的直接显示
                            st.success(f"✅ 重置链接已发送到 {mask_email(email)}")
                            logger.info(f"密码重置请求: {mask_email(email)}")
                            st.rerun()
                        else:
                            # 为安全起见，不透露邮箱是否存在
                            st.info("📧 如果该邮箱已注册，您将收到重置链接")
    else:
        # 步骤2: 输入新密码
        st.info(f"📧 正在为 {mask_email(st.session_state.get('reset_email', ''))} 重置密码")
        
        with st.form("reset_password_form"):
            new_password = st.text_input(
                "新密码", 
                type="password",
                placeholder="请输入新密码（至少8位，包含字母和数字）"
            )
            confirm_password = st.text_input(
                "确认新密码", 
                type="password",
                placeholder="请再次输入新密码"
            )
            submit = st.form_submit_button("🔄 重置密码", use_container_width=True)
            
            if submit:
                handle_password_reset(new_password, confirm_password)
    
    # 返回登录
    st.markdown("---")
    if st.button("⬅️ 返回登录", use_container_width=True):
        st.session_state['show_password_reset'] = False
        st.session_state['reset_token_sent'] = False
        st.session_state.pop('reset_email', None)
        st.session_state.pop('reset_token', None)
        st.rerun()


def handle_password_reset(new_password: str, confirm_password: str):
    """处理密码重置"""
    if not new_password or not confirm_password:
        st.error("❌ 请填写所有字段")
        return
    
    if new_password != confirm_password:
        st.error("❌ 两次密码输入不一致")
        return
    
    if len(new_password) < 8:
        st.error("❌ 密码至少需要8个字符")
        return
    
    # 验证令牌
    reset_token = st.session_state.get('reset_token')
    email = verify_password_reset_token(reset_token)
    
    if not email:
        st.error("❌ 重置链接已过期，请重新申请")
        st.session_state['reset_token_sent'] = False
        return
    
    try:
        # 重置密码
        success = UserAuth.reset_password(email, new_password)
        if success:
            st.success("✅ 密码重置成功！请使用新密码登录")
            logger.info(f"密码重置成功: {mask_email(email)}")
            
            # 清理状态
            st.session_state['show_password_reset'] = False
            st.session_state['reset_token_sent'] = False
            st.session_state.pop('reset_email', None)
            st.session_state.pop('reset_token', None)
        else:
            st.error("❌ 密码重置失败，请稍后重试")
            
    except AuthenticationError as e:
        st.error(f"❌ {e}")
    except Exception as e:
        st.error("❌ 系统错误，请稍后重试")
        logger.error(f"密码重置异常: {e}", exc_info=True)


def show_user_info():
    """显示已登录用户信息"""
    st.subheader(f"👋 欢迎，{st.session_state.get('username', '用户')}！")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info(f"📧 邮箱: {mask_email(st.session_state.get('email', ''))}")
    
    with col2:
        if st.button("🚪 退出登录", use_container_width=True):
            handle_logout()


def handle_logout():
    """处理登出"""
    username = st.session_state.get('username', 'Unknown')
    
    # 清除会话
    session_data = SessionManager.clear_session()
    for key, value in session_data.items():
        st.session_state[key] = value
    
    logger.info(f"用户 {username} 已登出")
    st.success("✅ 已成功退出登录")
    st.rerun()


def show_login_page():
    """
    显示登录界面主函数
    """
    init_session_state()
    
    st.title("🔐 SmartAudit 用户认证")
    
    # 检查是否已登录
    if st.session_state.get('logged_in', False):
        show_user_info()
        
        st.markdown("---")
        st.info("💡 您已登录，可以前往其他页面使用系统功能")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("📊 前往仪表板", use_container_width=True):
                st.session_state['page'] = 'dashboard'
                st.rerun()
        with col2:
            if st.button("📜 查看历史记录", use_container_width=True):
                st.session_state['page'] = 'history'
                st.rerun()
        with col3:
            if st.button("📈 查看统计", use_container_width=True):
                st.session_state['page'] = 'statistics'
                st.rerun()
    else:
        # 显示登录或密码重置表单
        if st.session_state.get('show_password_reset', False):
            show_password_reset_form()
        else:
            show_login_form()
            
            # 显示登录提示
            with st.expander("💡 登录帮助"):
                st.markdown("""
                **如何登录：**
                1. 输入您的用户名或注册邮箱
                2. 输入密码
                3. 点击"登录"按钮
                
                **忘记密码？**
                - 点击"忘记密码"按钮
                - 输入注册邮箱
                - 按照提示重置密码
                
                **还没有账户？**
                - 点击"注册新账户"按钮创建账户
                """)


if __name__ == "__main__":
    show_login_page()
