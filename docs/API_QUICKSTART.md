# 🚀 API 快速参考指南

本文档为 Auditor AI REST API 的快速参考，适合开发者快速上手。

## 启动 API 服务

```bash
# 方式1: 直接运行
python api.py

# 方式2: 使用 uvicorn
uvicorn api:app --host 0.0.0.0 --port 8000 --reload

# 方式3: 指定端口
uvicorn api:app --port 8080
```

服务启动后：
- **API 地址**: http://localhost:8000
- **Swagger 文档**: http://localhost:8000/docs
- **ReDoc 文档**: http://localhost:8000/redoc
- **健康检查**: http://localhost:8000/health

## 环境变量

确保 `.env` 文件包含必要的配置：

```env
GOOGLE_API_KEY=your_gemini_api_key_here
```

## 完整工作流程示例

### 1. 用户注册

```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "password": "mypassword123"
  }'
```

**响应示例:**
```json
{
  "user_id": "1",
  "username": "alice",
  "email": "alice@example.com"
}
```

### 2. 用户登录

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "mypassword123"
  }'
```

**响应示例:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "user_id": "1"
}
```

**保存 token 供后续使用:**
```bash
export TOKEN="eyJ0eXAiOiJKV1QiLCJhbGc..."
```

### 3. 创建审计报告

```bash
curl -X POST http://localhost:8000/api/audits \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "raw_input": "pragma solidity ^0.8.0;\n\ncontract MyContract {\n    function withdraw() public {\n        // vulnerable code\n    }\n}",
    "target_name": "MyContract",
    "extra_metadata": {
      "network": "Ethereum",
      "compiler_version": "0.8.0"
    }
  }'
```

**响应示例:**
```json
{
  "id": "audit-123",
  "user_id": "1",
  "created_at": "2026-01-23T10:30:00Z",
  "target_name": "MyContract",
  "raw_input": "pragma solidity ^0.8.0;...",
  "heuristic_alerts": [
    "⚠️ Warning: Potential issue detected"
  ],
  "full_markdown_report": "## Analysis for: `withdraw`\n\n### Vulnerability: Reentrancy...",
  "functions": [
    {
      "id": "func-1",
      "function_name": "withdraw",
      "source_code": "function withdraw() public {...}",
      "markdown_report": "### Vulnerability: ...",
      "vulnerabilities": [
        {
          "id": "vuln-1",
          "title": "Reentrancy Vulnerability",
          "severity": "Critical",
          "description": "...",
          "recommendation": "...",
          "suggested_code": "..."
        }
      ]
    }
  ],
  "extra_metadata": {
    "network": "Ethereum",
    "compiler_version": "0.8.0"
  }
}
```

### 4. 列出审计历史

```bash
curl -X GET "http://localhost:8000/api/audits?limit=10&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

**响应示例:**
```json
[
  {
    "id": "audit-123",
    "target_name": "MyContract",
    "created_at": "2026-01-23T10:30:00Z"
  },
  {
    "id": "audit-122",
    "target_name": "AnotherContract",
    "created_at": "2026-01-22T15:20:00Z"
  }
]
```

### 5. 获取审计详情

```bash
curl -X GET http://localhost:8000/api/audits/audit-123 \
  -H "Authorization: Bearer $TOKEN"
```

### 6. 获取统计信息

```bash
curl -X GET http://localhost:8000/api/stats/summary \
  -H "Authorization: Bearer $TOKEN"
```

**响应示例:**
```json
{
  "total_audits": 12,
  "last_7_days": 3,
  "severity_distribution": {
    "Critical": 1,
    "High": 2,
    "Medium": 4,
    "Low": 3,
    "Informational": 2
  }
}
```

## Python 客户端示例

```python
import requests
from typing import Optional

class AuditorAPIClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.token: Optional[str] = None
    
    def register(self, username: str, email: str, password: str) -> dict:
        """Register a new user."""
        response = requests.post(
            f"{self.base_url}/api/auth/register",
            json={"username": username, "email": email, "password": password}
        )
        response.raise_for_status()
        return response.json()
    
    def login(self, username: str, password: str) -> dict:
        """Login and store the access token."""
        response = requests.post(
            f"{self.base_url}/api/auth/login",
            json={"username": username, "password": password}
        )
        response.raise_for_status()
        data = response.json()
        self.token = data["access_token"]
        return data
    
    def create_audit(
        self,
        raw_input: str,
        target_name: Optional[str] = None,
        extra_metadata: Optional[dict] = None
    ) -> dict:
        """Create a new audit."""
        if not self.token:
            raise ValueError("Not authenticated. Call login() first.")
        
        response = requests.post(
            f"{self.base_url}/api/audits",
            headers={"Authorization": f"Bearer {self.token}"},
            json={
                "raw_input": raw_input,
                "target_name": target_name,
                "extra_metadata": extra_metadata or {}
            }
        )
        response.raise_for_status()
        return response.json()
    
    def list_audits(self, limit: int = 50, offset: int = 0) -> list:
        """List audits for the current user."""
        if not self.token:
            raise ValueError("Not authenticated. Call login() first.")
        
        response = requests.get(
            f"{self.base_url}/api/audits",
            headers={"Authorization": f"Bearer {self.token}"},
            params={"limit": limit, "offset": offset}
        )
        response.raise_for_status()
        return response.json()
    
    def get_audit(self, audit_id: str) -> dict:
        """Get a single audit report."""
        if not self.token:
            raise ValueError("Not authenticated. Call login() first.")
        
        response = requests.get(
            f"{self.base_url}/api/audits/{audit_id}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        response.raise_for_status()
        return response.json()
    
    def get_stats(self) -> dict:
        """Get audit statistics."""
        if not self.token:
            raise ValueError("Not authenticated. Call login() first.")
        
        response = requests.get(
            f"{self.base_url}/api/stats/summary",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        response.raise_for_status()
        return response.json()


# 使用示例
if __name__ == "__main__":
    client = AuditorAPIClient()
    
    # 注册并登录
    client.register("testuser", "test@example.com", "password123")
    client.login("testuser", "password123")
    
    # 创建审计
    contract_code = """
    pragma solidity ^0.8.0;
    
    contract Vulnerable {
        function withdraw() public {
            // vulnerable code
        }
    }
    """
    audit = client.create_audit(
        raw_input=contract_code,
        target_name="VulnerableContract"
    )
    print(f"Audit created: {audit['id']}")
    
    # 列出审计
    audits = client.list_audits(limit=10)
    print(f"Total audits: {len(audits)}")
    
    # 获取统计
    stats = client.get_stats()
    print(f"Total audits: {stats.get('total_audits', 0)}")
```

## 常见错误处理

### 401 Unauthorized
```json
{
  "detail": "Not authenticated. Missing Authorization header."
}
```
**解决方案**: 确保在请求头中包含 `Authorization: Bearer <token>`

### 404 Not Found
```json
{
  "detail": "Audit not found or access denied."
}
```
**解决方案**: 检查 audit_id 是否正确，或确认该审计属于当前用户

### 422 Validation Error
```json
{
  "detail": [
    {
      "loc": ["body", "password"],
      "msg": "ensure this value has at least 6 characters",
      "type": "value_error.any_str.min_length"
    }
  ]
}
```
**解决方案**: 检查请求体是否符合 API schema 要求

### 501 Not Implemented
```json
{
  "detail": "Audit creation is not implemented yet. Waiting for audit_service & database."
}
```
**说明**: 该端点尚未实现，等待相关模块完成（开发阶段）

## Postman 使用

1. **导入集合**:
   - 打开 Postman
   - File → Import
   - 选择 `Auditor_AI_API.postman_collection.json`

2. **设置环境变量**:
   - 创建新环境或使用默认环境
   - 添加变量 `base_url` = `http://localhost:8000`

3. **自动保存 Token**:
   - Login 请求会自动将 `access_token` 保存到环境变量
   - 后续请求会自动使用该 token

4. **测试流程**:
   - 先运行 "Register User" 或直接 "Login"
   - 运行 "Create Audit" 创建审计
   - 运行 "List Audits" 查看历史
   - 运行 "Get Audit Detail" 查看详情

## 开发状态

⚠️ **注意**: 当前 API 处于开发阶段，部分端点返回 `501 Not Implemented`，等待以下模块完成：

- ✅ API 路由结构已就绪
- ✅ Pydantic 模型已定义
- ⏳ 等待认证模块 (`src/auth.py`, `src/security.py`)
- ⏳ 等待审计服务 (`src/audit_service.py`)
- ⏳ 等待数据库模块 (`src/database.py`)

一旦这些模块就绪，API 端点将自动激活。

## 更多信息

- **完整 API 文档**: 访问 http://localhost:8000/docs (Swagger UI)
- **接口定义**: 查看 `docs/INTERFACES.md`
- **任务清单**: 查看 `docs/TASKS.md`
