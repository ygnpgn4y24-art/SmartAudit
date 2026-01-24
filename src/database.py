"""
数据库模型和配置
使用 SQLAlchemy ORM 进行数据库管理
"""
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import os

Base = declarative_base()

class User(Base):
    """用户模型"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # 关系
    audits = relationship("AuditReport", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"


class AuditReport(Base):
    """审计报告模型"""
    __tablename__ = 'audit_reports'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    contract_code = Column(Text, nullable=False)
    contract_name = Column(String(100))
    heuristic_results = Column(Text)  # JSON格式存储启发式检查结果
    ai_analysis = Column(Text)  # AI分析结果
    severity_score = Column(Float)  # 严重性评分 0-10
    vulnerabilities_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    analysis_duration = Column(Float)  # 分析耗时（秒）
    
    # 关系
    user = relationship("User", back_populates="audits")
    vulnerabilities = relationship("Vulnerability", back_populates="audit_report", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<AuditReport(id={self.id}, contract='{self.contract_name}', user_id={self.user_id})>"


class Vulnerability(Base):
    """漏洞详情模型"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    audit_report_id = Column(Integer, ForeignKey('audit_reports.id'), nullable=False)
    name = Column(String(100), nullable=False)
    severity = Column(String(20))  # Critical, High, Medium, Low, Informational
    description = Column(Text)
    recommendation = Column(Text)
    line_number = Column(Integer)
    function_name = Column(String(100))
    
    # 关系
    audit_report = relationship("AuditReport", back_populates="vulnerabilities")
    
    def __repr__(self):
        return f"<Vulnerability(name='{self.name}', severity='{self.severity}')>"


class DatabaseManager:
    """数据库管理器"""
    
    def __init__(self, db_url=None):
        if db_url is None:
            # 默认使用 SQLite
            db_url = os.getenv("DATABASE_URL", "sqlite:///smartaudit.db")
        
        self.engine = create_engine(db_url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)
    
    def create_tables(self):
        """创建所有表"""
        Base.metadata.create_all(self.engine)
    
    def drop_tables(self):
        """删除所有表（谨慎使用）"""
        Base.metadata.drop_all(self.engine)
    
    def get_session(self):
        """获取数据库会话"""
        return self.SessionLocal()
    
    def close_session(self, session):
        """关闭数据库会话"""
        session.close()
    
    def reset_database(self):
        """重置数据库（删除所有表后重新创建）"""
        print("⚠️  警告：即将删除所有数据！")
        self.drop_tables()
        print("✅ 已删除所有表")
        self.create_tables()
        print("✅ 已重新创建所有表")
    
    def get_table_names(self):
        """获取所有表名"""
        return Base.metadata.tables.keys()
    
    def check_connection(self):
        """检查数据库连接"""
        try:
            with self.engine.connect() as conn:
                return True
        except Exception as e:
            print(f"❌ 数据库连接失败: {e}")
            return False


# 全局数据库管理器实例
db_manager = DatabaseManager()


def init_database():
    """初始化数据库"""
    db_manager.create_tables()
    print("数据库初始化完成！")


if __name__ == "__main__":
    # 运行此脚本以初始化数据库
    init_database()
