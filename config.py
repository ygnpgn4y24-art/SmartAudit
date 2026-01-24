"""
项目配置文件
集中管理所有配置项
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 项目根目录
BASE_DIR = Path(__file__).parent

# 数据库配置
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///smartaudit.db")

# Google API配置
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# FAISS索引路径
FAISS_INDEX_PATH = BASE_DIR / "faiss_index"

# 知识库路径
KNOWLEDGE_BASE_PATH = BASE_DIR / "knowledge_base"

# 日志配置
LOG_FILE = BASE_DIR / "logs" / "smartaudit.log"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Session配置
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
SESSION_TIMEOUT = 3600  # 1小时

# API配置
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

# JWT配置
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Streamlit配置
STREAMLIT_SERVER_PORT = int(os.getenv("STREAMLIT_PORT", "8501"))

# RAG配置
RAG_CHUNK_SIZE = 1000
RAG_CHUNK_OVERLAP = 200
RAG_RETRIEVAL_K = 5  # 检索Top K个相关文档

# 审计配置
MAX_CODE_LENGTH = 50000  # 最大代码长度
ANALYSIS_TIMEOUT = 300  # 分析超时时间（秒）

# 导出配置
EXPORT_DIR = BASE_DIR / "exports"
EXPORT_DIR.mkdir(exist_ok=True)
