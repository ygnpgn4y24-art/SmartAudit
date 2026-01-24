"""
数据库初始化脚本 - 成员1完成

运行此脚本以初始化数据库表结构
"""
import sys
from src.database import db_manager, User, AuditReport, Vulnerability
from src.logger_config import logger


def init_database(reset=False):
    """
    初始化数据库表
    
    Args:
        reset: 是否重置数据库（删除所有数据）
    """
    try:
        print("=" * 50)
        print("🚀 SmartAudit 数据库初始化")
        print("=" * 50)
        
        # 检查连接
        print("\n1️⃣ 检查数据库连接...")
        if not db_manager.check_connection():
            raise Exception("无法连接到数据库")
        print("   ✅ 数据库连接正常")
        
        # 重置或创建
        if reset:
            print("\n2️⃣ 重置数据库（删除所有数据）...")
            db_manager.reset_database()
        else:
            print("\n2️⃣ 创建数据库表...")
            logger.info("开始初始化数据库...")
            db_manager.create_tables()
            logger.info("✅ 数据库初始化成功！")
            print("   ✅ 数据库表创建成功！")
        
        # 显示创建的表
        print("\n3️⃣ 已创建的表：")
        for table_name in db_manager.get_table_names():
            print(f"   📋 {table_name}")
        
        # 验证表结构
        print("\n4️⃣ 验证表结构...")
        session = db_manager.get_session()
        try:
            # 测试查询（应该返回空结果）
            user_count = session.query(User).count()
            audit_count = session.query(AuditReport).count()
            vuln_count = session.query(Vulnerability).count()
            
            print(f"   ✅ users 表: {user_count} 条记录")
            print(f"   ✅ audit_reports 表: {audit_count} 条记录")
            print(f"   ✅ vulnerabilities 表: {vuln_count} 条记录")
            
        finally:
            db_manager.close_session(session)
        
        print("\n" + "=" * 50)
        print("🎉 数据库初始化完成！")
        print("=" * 50)
        print("\n📝 下一步：")
        print("   - 运行 'python -m src.rag_core' 构建知识库")
        print("   - 运行 'streamlit run app.py' 启动应用")
        print("   - 运行 'pytest tests/' 运行测试")
        print()
        
    except Exception as e:
        logger.error(f"❌ 数据库初始化失败: {e}", exc_info=True)
        print(f"\n❌ 数据库初始化失败: {e}")
        print("\n💡 可能的解决方案：")
        print("   - 检查 .env 文件中的 DATABASE_URL 配置")
        print("   - 确保有数据库文件的写权限")
        print("   - 如果使用PostgreSQL，确保数据库服务已启动")
        sys.exit(1)


def create_demo_data():
    """创建演示数据（可选）"""
    from src.auth import UserAuth
    
    print("\n📦 创建演示数据...")
    
    try:
        # 创建演示用户
        user = UserAuth.register_user(
            username="demo",
            email="demo@smartaudit.com",
            password="demo123"
        )
        print(f"   ✅ 创建演示用户: {user.username}")
        
        print("\n✨ 演示数据创建成功！")
        print("   用户名: demo")
        print("   密码: demo123")
        
    except Exception as e:
        print(f"   ⚠️  演示数据创建失败（可能已存在）: {e}")


if __name__ == "__main__":
    # 解析命令行参数
    import argparse
    parser = argparse.ArgumentParser(description='初始化SmartAudit数据库')
    parser.add_argument('--reset', action='store_true', help='重置数据库（删除所有数据）')
    parser.add_argument('--demo', action='store_true', help='创建演示数据')
    args = parser.parse_args()
    
    # 初始化数据库
    init_database(reset=args.reset)
    
    # 创建演示数据
    if args.demo:
        create_demo_data()
