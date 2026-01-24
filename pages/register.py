"""
成员2 - Streamlit注册页面
提供用户注册界面和表单验证功能
"""
import streamlit as st
from src.auth import UserAuth, AuthenticationError
from src.security import (
    SessionManager,
    validate_password_strength,
    validate_email,
    validate_username,
    sanitize_input
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
        'registration_step': 1
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def validate_form_input(username: str, email: str, password: str, password_confirm: str) -> tuple:
    """
    验证表单输入
    
    Returns:
        tuple: (is_valid, errors_list)
    """
    errors = []
    
    # 验证用户名
    if not username:
        errors.append("请输入用户名")
    else:
        username = sanitize_input(username)
        is_valid, msg = validate_username(username)
        if not is_valid:
            errors.append(msg)
    
    # 验证邮箱
    if not email:
        errors.append("请输入邮箱")
    else:
        is_valid, msg = validate_email(email)
        if not is_valid:
            errors.append(msg)
    
    # 验证密码
    if not password:
        errors.append("请输入密码")
    else:
        is_valid, msg = validate_password_strength(password)
        if not is_valid:
            errors.append(msg)
    
    # 验证密码确认
    if not password_confirm:
        errors.append("请确认密码")
    elif password != password_confirm:
        errors.append("两次密码输入不一致")
    
    return len(errors) == 0, errors


def check_availability(username: str, email: str) -> tuple:
    """
    检查用户名和邮箱是否可用
    
    Returns:
        tuple: (is_available, errors_list)
    """
    errors = []
    exists = UserAuth.check_user_exists(username, email)
    
    if exists.get('username_exists'):
        errors.append("用户名已被使用，请选择其他用户名")
    
    if exists.get('email_exists'):
        errors.append("邮箱已被注册，请使用其他邮箱或直接登录")
    
    return len(errors) == 0, errors


def show_password_strength_indicator(password: str):
    """显示密码强度指示器"""
    if not password:
        return
    
    strength = 0
    feedback = []
    
    if len(password) >= 8:
        strength += 1
    else:
        feedback.append("长度至少8位")
    
    if len(password) >= 12:
        strength += 1
    
    if any(c.isupper() for c in password):
        strength += 1
    else:
        feedback.append("包含大写字母")
    
    if any(c.islower() for c in password):
        strength += 1
    else:
        feedback.append("包含小写字母")
    
    if any(c.isdigit() for c in password):
        strength += 1
    else:
        feedback.append("包含数字")
    
    if any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
        strength += 1
    else:
        feedback.append("包含特殊字符")
    
    # 显示强度条
    strength_colors = {
        0: "🔴", 1: "🔴", 2: "🟠", 
        3: "🟡", 4: "🟢", 5: "🟢", 6: "💚"
    }
    strength_labels = {
        0: "很弱", 1: "弱", 2: "一般",
        3: "中等", 4: "强", 5: "很强", 6: "极强"
    }
    
    color = strength_colors.get(strength, "🔴")
    label = strength_labels.get(strength, "很弱")
    
    progress = min(strength / 6, 1.0)
    
    st.caption(f"密码强度: {color} {label}")
    st.progress(progress)
    
    if feedback:
        st.caption(f"💡 建议添加: {', '.join(feedback)}")


def show_registration_form():
    """显示注册表单"""
    st.subheader("📝 创建新账户")
    
    # 用户协议
    with st.expander("📜 用户协议与隐私政策", expanded=False):
        st.markdown("""
        **用户协议：**
        1. 您同意按照本系统的使用规范使用本服务
        2. 您承诺提供真实、准确的注册信息
        3. 您负责保管好自己的账户密码
        
        **隐私政策：**
        1. 我们仅收集必要的用户信息
        2. 您的密码会经过加密存储
        3. 我们不会将您的信息分享给第三方
        """)
    
    with st.form("register_form", clear_on_submit=False):
        # 用户名输入
        username = st.text_input(
            "用户名 *",
            placeholder="3-50个字符，支持字母、数字、下划线和连字符",
            help="用户名将作为您的唯一标识，设置后可以修改"
        )
        
        # 邮箱输入
        email = st.text_input(
            "邮箱 *",
            placeholder="your@email.com",
            help="邮箱用于登录和找回密码"
        )
        
        # 密码输入
        password = st.text_input(
            "密码 *",
            type="password",
            placeholder="至少8个字符，包含字母和数字",
            help="建议使用包含大小写字母、数字和特殊字符的强密码"
        )
        
        # 确认密码
        password_confirm = st.text_input(
            "确认密码 *",
            type="password",
            placeholder="再次输入密码"
        )
        
        # 用户协议勾选
        agree_terms = st.checkbox(
            "我已阅读并同意《用户协议》和《隐私政策》",
            value=False
        )
        
        # 提交按钮
        col1, col2 = st.columns([1, 1])
        with col1:
            submit = st.form_submit_button("🚀 立即注册", use_container_width=True)
        with col2:
            st.form_submit_button("🔄 重置表单", use_container_width=True)
        
        if submit:
            if not agree_terms:
                st.error("❌ 请先阅读并同意用户协议和隐私政策")
            else:
                handle_registration(username, email, password, password_confirm)
    
    # 密码强度指示器（在表单外显示）
    if password:
        show_password_strength_indicator(password)
    
    # 登录链接
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.write("已有账户？")
    with col2:
        if st.button("🔑 前往登录", use_container_width=True):
            st.session_state['page'] = 'login'
            st.rerun()


def handle_registration(username: str, email: str, password: str, password_confirm: str):
    """处理注册逻辑"""
    # 清理输入
    username = sanitize_input(username.strip()) if username else ""
    email = email.strip().lower() if email else ""
    
    # 表单验证
    is_valid, errors = validate_form_input(username, email, password, password_confirm)
    if not is_valid:
        for error in errors:
            st.error(f"❌ {error}")
        return
    
    # 检查可用性
    is_available, errors = check_availability(username, email)
    if not is_available:
        for error in errors:
            st.error(f"❌ {error}")
        return
    
    try:
        # 创建用户
        user = UserAuth.register_user(username, email, password)
        
        st.success("✅ 注册成功！正在自动登录...")
        logger.info(f"新用户注册: {username}, 邮箱: {email}")
        
        # 自动登录 - 创建会话
        session_data = SessionManager.create_session({
            'id': user.id,
            'username': user.username,
            'email': user.email
        })
        
        # 保存到session_state
        for key, value in session_data.items():
            st.session_state[key] = value
        
        st.balloons()
        st.rerun()
        
    except AuthenticationError as e:
        st.error(f"❌ 注册失败: {e}")
        logger.warning(f"注册失败 - 用户: {username}, 原因: {e}")
    except Exception as e:
        st.error("❌ 系统错误，请稍后重试")
        logger.error(f"注册异常: {e}", exc_info=True)


def show_registered_info():
    """显示已注册用户信息"""
    st.subheader(f"👋 您好，{st.session_state.get('username', '用户')}！")
    
    st.success("✅ 您已成功登录")
    
    st.info("""
    🎉 恭喜您完成注册！
    
    您现在可以：
    - 使用智能合约审计功能
    - 查看审计历史记录
    - 导出审计报告
    """)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📊 前往仪表板", use_container_width=True):
            st.session_state['page'] = 'dashboard'
            st.rerun()
    with col2:
        if st.button("🔍 开始审计", use_container_width=True):
            st.session_state['page'] = 'audit'
            st.rerun()
    with col3:
        if st.button("⚙️ 账户设置", use_container_width=True):
            st.session_state['page'] = 'settings'
            st.rerun()


def show_register_page():
    """
    显示注册界面主函数
    """
    init_session_state()
    
    st.title("📝 SmartAudit 用户注册")
    
    # 检查是否已登录
    if st.session_state.get('logged_in', False):
        show_registered_info()
    else:
        show_registration_form()
        
        # 注册须知
        with st.expander("❓ 注册须知"):
            st.markdown("""
            **账户信息要求：**
            
            1. **用户名**
               - 长度: 3-50个字符
               - 允许: 字母、数字、下划线(_)、连字符(-)
               - 不允许: 空格、特殊字符
            
            2. **邮箱**
               - 必须是有效的邮箱格式
               - 用于登录和密码找回
            
            3. **密码**
               - 长度: 至少8个字符
               - 必须包含: 至少一个字母和一个数字
               - 建议: 使用大小写字母、数字和特殊字符的组合
            
            **安全提示：**
            - 请使用强密码保护您的账户
            - 不要在多个网站使用相同密码
            - 定期更换密码以提高安全性
            """)


if __name__ == "__main__":
    show_register_page()
