# 数据库设计文档

## 📊 ER图

```
┌─────────────────┐
│     Users       │
├─────────────────┤
│ id (PK)         │
│ username        │
│ email           │
│ password_hash   │
│ created_at      │
│ is_active       │
└────────┬────────┘
         │ 1
         │
         │ N
┌────────┴────────────────┐
│   AuditReports          │
├─────────────────────────┤
│ id (PK)                 │
│ user_id (FK)            │
│ contract_code           │
│ contract_name           │
│ heuristic_results       │
│ ai_analysis             │
│ severity_score          │
│ vulnerabilities_count   │
│ created_at              │
│ analysis_duration       │
└───────────┬─────────────┘
            │ 1
            │
            │ N
┌───────────┴──────────────┐
│   Vulnerabilities        │
├──────────────────────────┤
│ id (PK)                  │
│ audit_report_id (FK)     │
│ name                     │
│ severity                 │
│ description              │
│ recommendation           │
│ line_number              │
│ function_name            │
└──────────────────────────┘
```

---

## 📋 表结构详细说明

### Users表
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
```

**字段说明**：
- `id`: 主键，自增
- `username`: 用户名，唯一索引
- `email`: 邮箱，唯一索引
- `password_hash`: 密码哈希（PBKDF2/bcrypt）
- `created_at`: 注册时间
- `is_active`: 账户状态（用于禁用账户）

---

### AuditReports表
```sql
CREATE TABLE audit_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    contract_code TEXT NOT NULL,
    contract_name VARCHAR(100),
    heuristic_results TEXT,
    ai_analysis TEXT,
    severity_score REAL,
    vulnerabilities_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    analysis_duration REAL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_audit_reports_user_id ON audit_reports(user_id);
CREATE INDEX idx_audit_reports_created_at ON audit_reports(created_at);
CREATE INDEX idx_audit_reports_severity ON audit_reports(severity_score);
```

**字段说明**：
- `id`: 主键，自增
- `user_id`: 外键，关联users表
- `contract_code`: 合约源代码（TEXT类型）
- `contract_name`: 合约名称（可选）
- `heuristic_results`: 启发式检查结果（JSON字符串）
- `ai_analysis`: AI分析结果（Markdown格式）
- `severity_score`: 严重性评分（0-10）
- `vulnerabilities_count`: 漏洞总数
- `created_at`: 审计时间
- `analysis_duration`: 分析耗时（秒）

**级联删除**：删除用户时，自动删除其所有审计报告

---

### Vulnerabilities表
```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_report_id INTEGER NOT NULL,
    name VARCHAR(100) NOT NULL,
    severity VARCHAR(20),
    description TEXT,
    recommendation TEXT,
    line_number INTEGER,
    function_name VARCHAR(100),
    FOREIGN KEY (audit_report_id) REFERENCES audit_reports(id) ON DELETE CASCADE
);

CREATE INDEX idx_vulnerabilities_report_id ON vulnerabilities(audit_report_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_name ON vulnerabilities(name);
```

**字段说明**：
- `id`: 主键，自增
- `audit_report_id`: 外键，关联audit_reports表
- `name`: 漏洞名称（如"Reentrancy"）
- `severity`: 严重级别（Critical/High/Medium/Low/Informational）
- `description`: 漏洞描述
- `recommendation`: 修复建议
- `line_number`: 代码行号（可选）
- `function_name`: 函数名称（可选）

**级联删除**：删除审计报告时，自动删除所有关联的漏洞记录

---

## 🔍 常用查询示例

### 查询用户的所有审计报告
```sql
SELECT * FROM audit_reports 
WHERE user_id = 1 
ORDER BY created_at DESC 
LIMIT 10;
```

### 查询某个审计报告的所有漏洞
```sql
SELECT * FROM vulnerabilities 
WHERE audit_report_id = 123;
```

### 统计用户的漏洞类型分布
```sql
SELECT v.severity, COUNT(*) as count
FROM vulnerabilities v
JOIN audit_reports ar ON v.audit_report_id = ar.id
WHERE ar.user_id = 1
GROUP BY v.severity;
```

### 查询最近7天的审计数
```sql
SELECT COUNT(*) FROM audit_reports
WHERE user_id = 1 
AND created_at >= datetime('now', '-7 days');
```

### Top 10最常见的漏洞
```sql
SELECT name, COUNT(*) as count
FROM vulnerabilities
GROUP BY name
ORDER BY count DESC
LIMIT 10;
```

---

## 🔧 数据库迁移

使用Alembic进行数据库版本管理：

```bash
# 初始化迁移
alembic init migrations

# 创建迁移
alembic revision --autogenerate -m "Initial schema"

# 执行迁移
alembic upgrade head

# 回滚迁移
alembic downgrade -1
```

---

## 📈 性能优化建议

1. **索引优化**：
   - 为常用查询字段添加索引（username, email, user_id, created_at）
   - 复合索引用于多条件查询

2. **分页查询**：
   - 使用LIMIT和OFFSET进行分页
   - 避免一次性加载大量数据

3. **级联删除**：
   - 使用数据库级联删除，减少应用层操作

4. **数据归档**：
   - 定期归档旧审计报告
   - 保持主表数据量适中

---

## 🔒 数据安全

1. **密码存储**：永远不存储明文密码，使用PBKDF2/bcrypt加密
2. **SQL注入防护**：使用ORM参数化查询
3. **数据备份**：定期备份数据库
4. **访问控制**：确保用户只能访问自己的数据

---

## 📝 注意事项

- SQLite用于开发和测试，生产环境建议使用PostgreSQL/MySQL
- TEXT字段可能影响性能，考虑大文件存储到对象存储
- 定期清理测试数据
- 监控数据库大小和查询性能
