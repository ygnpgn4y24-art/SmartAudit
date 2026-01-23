# 团队成员与分工

## 👥 团队组成

### 成员1 - 数据库架构师
**职责**：数据层基础设施
- 负责数据库设计与实现
- 提供数据访问层API
- 管理数据库迁移

**主要文件**：
- `src/database.py`
- `src/models.py`
- `init_db.py`
- `migrations/`

---

### 成员2 - 认证与安全专家
**职责**：用户认证与权限管理
- 实现用户注册/登录
- 密码加密与Token管理
- 权限控制

**主要文件**：
- `src/auth.py`
- `src/security.py`
- `pages/login.py`
- `pages/register.py`

---

### 成员3 - 审计服务工程师
**职责**：审计核心业务逻辑
- 改造审计逻辑集成数据库
- 实现审计报告管理
- 漏洞数据处理

**主要文件**：
- `src/audit_service.py`
- `src/logic.py` (改造)
- `pages/history.py`
- `pages/report_detail.py`

---

### 成员4 - 前端与可视化工程师
**职责**：用户界面与数据可视化
- 改造Streamlit界面
- 实现数据可视化
- 报告导出功能

**主要文件**：
- `app.py` (改造)
- `pages/dashboard.py`
- `pages/statistics.py`
- `src/visualization.py`
- `src/export_service.py`

---

### 成员5 - API与集成工程师
**职责**：RESTful API开发
- 搭建FastAPI服务
- 实现API端点
- API文档生成

**主要文件**：
- `api.py`
- `src/api_routes/`
- `src/api_schemas.py`
- `src/api_middleware.py`

---

### 成员6 - 测试与DevOps工程师
**职责**：质量保证与部署
- 编写测试用例
- 配置CI/CD
- Docker容器化

**主要文件**：
- `tests/`
- `Dockerfile`
- `docker-compose.yml`
- `.github/workflows/ci.yml`

---

## 📅 开发时间线

### Week 1: 基础设施
- Day 1-2: 成员1完成数据库设计
- Day 3-5: 成员2、3开始开发（依赖数据库）

### Week 2: 业务功能
- Day 1-3: 成员2、3完成核心功能
- Day 4-5: 成员4、5开始开发

### Week 3: 集成与测试
- Day 1-3: 成员6编写测试
- Day 4-5: 全员集成与修复

---

## 🔄 协作流程

1. **每日站会**（15分钟）
   - 汇报进度
   - 提出问题
   - 同步接口变更

2. **代码审查**
   - 每个PR需要至少1人审查
   - 通过所有测试才能合并

3. **文档更新**
   - 接口变更及时更新文档
   - 完成功能更新README

---

## 📞 联系方式

| 成员 | GitHub | 邮箱 | 负责模块 |
|------|--------|------|----------|
| 成员1 | @member1 | member1@email.com | 数据库 |
| 成员2 | @member2 | member2@email.com | 认证 |
| 成员3 | @member3 | member3@email.com | 审计服务 |
| 成员4 | @member4 | member4@email.com | 前端 |
| 成员5 | @member5 | member5@email.com | API |
| 成员6 | @member6 | member6@email.com | 测试 |
