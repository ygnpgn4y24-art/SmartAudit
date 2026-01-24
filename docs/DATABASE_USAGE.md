# 数据库使用指南 - 给其他成员

## 📚 快速开始

### 1. 导入数据库模块

```python
from src.database import db_manager, User, AuditReport, Vulnerability
```

### 2. 获取数据库会话

```python
# 获取会话
session = db_manager.get_session()

try:
    # 你的数据库操作
    pass
finally:
    # 务必关闭会话
    db_manager.close_session(session)
```

---

## 📋 常用操作示例

### 创建用户

```python
from src.database import db_manager, User

session = db_manager.get_session()
try:
    new_user = User(
        username="alice",
        email="alice@example.com",
        password_hash="hashed_password_here"
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)  # 刷新以获取自动生成的ID
    
    print(f"用户创建成功，ID: {new_user.id}")
    
finally:
    db_manager.close_session(session)
```

### 查询用户

```python
# 根据用户名查询
user = session.query(User).filter_by(username="alice").first()

# 根据邮箱查询
user = session.query(User).filter_by(email="alice@example.com").first()

# 根据ID查询
user = session.query(User).filter_by(id=1).first()

# 查询所有用户
all_users = session.query(User).all()

# 条件查询
active_users = session.query(User).filter(User.is_active == True).all()
```

### 创建审计报告

```python
from src.database import AuditReport
import json

audit = AuditReport(
    user_id=user.id,
    contract_code="pragma solidity ^0.8.0; ...",
    contract_name="MyContract",
    heuristic_results=json.dumps(["Alert 1", "Alert 2"]),
    ai_analysis="## Analysis result...",
    severity_score=5.5,
    vulnerabilities_count=3,
    analysis_duration=12.5
)
session.add(audit)
session.commit()
```

### 创建漏洞记录

```python
from src.database import Vulnerability

vuln = Vulnerability(
    audit_report_id=audit.id,
    name="Reentrancy",
    severity="High",
    description="Reentrancy vulnerability detected",
    recommendation="Use checks-effects-interactions pattern",
    line_number=25,
    function_name="withdraw"
)
session.add(vuln)
session.commit()
```

### 查询用户的所有审计

```python
# 方法1: 通过关系
user = session.query(User).filter_by(id=1).first()
audits = user.audits  # 直接访问关系属性

# 方法2: 通过查询
audits = session.query(AuditReport).filter_by(user_id=1).all()

# 方法3: 带排序
from sqlalchemy import desc
audits = session.query(AuditReport).filter_by(user_id=1).order_by(desc(AuditReport.created_at)).all()
```

### 查询审计报告的所有漏洞

```python
audit = session.query(AuditReport).filter_by(id=1).first()
vulnerabilities = audit.vulnerabilities  # 通过关系访问
```

### 更新数据

```python
user = session.query(User).filter_by(id=1).first()
user.is_active = False
session.commit()
```

### 删除数据

```python
# 删除单个记录
user = session.query(User).filter_by(id=1).first()
session.delete(user)
session.commit()

# 批量删除
session.query(User).filter_by(is_active=False).delete()
session.commit()
```

---

## 📊 统计查询示例

### 计数

```python
from sqlalchemy import func

# 总用户数
total_users = session.query(func.count(User.id)).scalar()

# 总审计数
total_audits = session.query(func.count(AuditReport.id)).scalar()
```

### 分组统计

```python
# 按严重性分组统计漏洞
severity_stats = session.query(
    Vulnerability.severity,
    func.count(Vulnerability.id)
).group_by(Vulnerability.severity).all()

for severity, count in severity_stats:
    print(f"{severity}: {count}")
```

### 平均值

```python
# 平均严重性评分
avg_score = session.query(func.avg(AuditReport.severity_score)).scalar()
```

### JOIN查询

```python
# 查询特定用户的所有漏洞
vulnerabilities = session.query(Vulnerability).join(
    AuditReport
).filter(
    AuditReport.user_id == 1
).all()
```

---

## ⚠️ 重要注意事项

### 1. 永远关闭会话

```python
# ❌ 错误：忘记关闭
session = db_manager.get_session()
user = session.query(User).first()
# 会话泄漏！

# ✅ 正确：使用try-finally
session = db_manager.get_session()
try:
    user = session.query(User).first()
finally:
    db_manager.close_session(session)
```

### 2. 处理异常

```python
session = db_manager.get_session()
try:
    # 数据库操作
    session.commit()
except Exception as e:
    session.rollback()  # 回滚失败的事务
    print(f"Error: {e}")
finally:
    db_manager.close_session(session)
```

### 3. 刷新对象获取最新数据

```python
user = User(username="test")
session.add(user)
session.commit()
session.refresh(user)  # 刷新以获取数据库生成的ID和时间戳
print(user.id)  # 现在有值了
```

### 4. 级联删除

删除用户时，相关的审计报告和漏洞会自动删除（已配置级联）：

```python
user = session.query(User).filter_by(id=1).first()
session.delete(user)
session.commit()
# 该用户的所有审计报告和漏洞也被删除了
```

---

## 🎯 给各成员的提示

### 成员2（认证）
你主要使用 `User` 模型：
```python
# 创建用户
user = User(username=..., email=..., password_hash=...)

# 查询用户
user = session.query(User).filter_by(username=username).first()
```

### 成员3（审计服务）
你主要使用 `AuditReport` 和 `Vulnerability` 模型：
```python
# 创建审计
audit = AuditReport(user_id=..., contract_code=..., ...)

# 添加漏洞
vuln = Vulnerability(audit_report_id=..., name=..., ...)
```

### 成员4（前端）
你通过其他成员的服务获取数据，不直接操作数据库

### 成员5（API）
你调用成员2、3的服务，不直接操作数据库（除非必要）

### 成员6（测试）
参考 `tests/conftest.py` 中的测试固件

---

## 🔍 调试技巧

### 查看SQL语句

```python
# 启用SQL日志
from sqlalchemy import create_engine
engine = create_engine(db_url, echo=True)  # echo=True 会打印SQL
```

### 查看对象状态

```python
from sqlalchemy import inspect

user = session.query(User).first()
insp = inspect(user)
print(insp.persistent)  # 是否持久化
print(insp.pending)     # 是否待提交
```

---

## 📞 遇到问题？

1. 检查是否初始化数据库：`python init_db.py`
2. 运行测试脚本：`python test_database_member1.py`
3. 查看日志：`logs/smartaudit.log`
4. 联系成员1

---

**成员1已完成数据库设计，祝大家开发顺利！** 🚀
