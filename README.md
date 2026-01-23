🤖 Auditor AI: AI-Powered Smart Contract Security Assistant
Auditor AI is a sophisticated, AI-powered tool designed to analyze Solidity smart contracts for potential security vulnerabilities. It leverages a Retrieval-Augmented Generation (RAG) architecture to provide deep, context-aware insights based on an industry-standard knowledge base.

This project showcases the practical application of Large Language Models (LLMs) to solve real-world problems in the Web3 ecosystem.

(Note: Replace this with an actual screenshot or GIF of your app)

✨ Key Features
Multi-Layered Analysis: Combines rapid heuristic checks for common issues with deep, AI-powered analysis for complex vulnerabilities.

Context-Aware Engine: Parses Solidity code to analyze functions individually, providing more precise and relevant feedback.

Structured Reporting: Delivers clear, actionable reports for each identified vulnerability, including severity level, description, and code suggestions.

Comprehensive Knowledge Base: The AI's analysis is grounded in a rich knowledge base curated from multiple, industry-leading security sources.

Professional Architecture: Built with a clean, modular structure, secure API key management, and robust logging for maintainability.

🧠 How It Works
Auditor AI employs a two-stage analysis process:

Heuristic Scanning: The input code is first scanned for simple, pattern-based vulnerabilities like tx.origin usage or outdated compiler versions. This provides immediate feedback on low-hanging fruit.

RAG-Powered Deep Analysis:

The Solidity code is parsed into individual functions.

For each function, the system queries a specialized FAISS vector store to retrieve the most relevant security information.

The function code and the retrieved context are then passed to a Large Language Model (e.g., GPT).

The LLM, acting as an expert security auditor, generates a structured analysis based on the provided context.

📚 Knowledge Base Sources
The intelligence of Auditor AI is built upon a curated collection of documents from the following highly-respected sources:

ConsenSys's Smart Contract Best Practices

Official Solidity Documentation - Security Considerations

The SWC Registry (Smart Contract Weakness Classification)

🚀 Getting Started
Follow these steps to run the application locally.

Prerequisites
Python 3.10+

A Google Gemini API Key

Installation
Clone the repository:

git clone [https://github.com/nonfungi/ai-smart-contract-auditor.git](https://github.com/nonfungi/ai-smart-contract-auditor.git)
cd ai-smart-contract-auditor

Create and activate a virtual environment:

python -m venv venv
# Windows
.\venv\Scripts\Activate
# macOS/Linux
source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Set up your environment variables:

Copy `env.example` to `.env` in the root of the project and add your key:

GOOGLE_API_KEY="..."

Build the Knowledge Base
Before running the app for the first time, you must build the vector store from the knowledge base files.

python -m src.rag_core

This will create a faiss_index directory in your project.

Run the Application

**Streamlit Web Interface:**
Once the knowledge base is built, you can start the web application:

```bash
streamlit run app.py
```
The application will open in your web browser.

**FastAPI REST API:**
To run the REST API server (for programmatic access or integration):

```bash
# Option 1: Using Python directly
python api.py

# Option 2: Using uvicorn directly
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at `http://localhost:8000`. Interactive API documentation (Swagger UI) is available at `http://localhost:8000/docs`.

🛠️ Technology Stack
Component	Technology
Web Framework	Streamlit
API Framework	FastAPI
AI / RAG	LangChain, Google Gemini API
Vector Store	FAISS (Facebook AI Similarity Search)
Code Parsing	solidity-parser
Environment	Python, python-dotenv

## 🔌 REST API Usage

The Auditor AI API provides programmatic access to all features via REST endpoints. This is useful for integration with other tools, CI/CD pipelines, or custom frontends.

### Quick Start

1. **Start the API server:**
   ```bash
   python api.py
   # or
   uvicorn api:app --host 0.0.0.0 --port 8000
   ```

2. **Access the interactive documentation:**
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

3. **Import Postman Collection:**
   - Import `Auditor_AI_API.postman_collection.json` into Postman
   - Set the `base_url` environment variable to `http://localhost:8000`
   - All requests are pre-configured with examples

### API Endpoints

#### Authentication

**Register a new user:**
```bash
curl -X POST "http://localhost:8000/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "securepassword123"
  }'
```

**Login and get access token:**
```bash
curl -X POST "http://localhost:8000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "securepassword123"
  }'
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "user_id": "1"
}
```

#### Audits

**Create a new audit:**
```bash
curl -X POST "http://localhost:8000/api/audits" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "raw_input": "pragma solidity ^0.8.0;\n\ncontract VulnerableContract {\n    mapping(address => uint256) public balances;\n    \n    function withdraw(uint256 amount) public {\n        require(balances[msg.sender] >= amount);\n        (bool success, ) = msg.sender.call{value: amount}(\"\");\n        require(success, \"Failed to send Ether\");\n        balances[msg.sender] -= amount;\n    }\n}",
    "target_name": "VulnerableContract",
    "extra_metadata": {
      "network": "Ethereum",
      "compiler_version": "0.8.0"
    }
  }'
```

**List audits (with pagination):**
```bash
curl -X GET "http://localhost:8000/api/audits?limit=50&offset=0" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Get audit details:**
```bash
curl -X GET "http://localhost:8000/api/audits/AUDIT_ID" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### Statistics

**Get audit statistics:**
```bash
curl -X GET "http://localhost:8000/api/stats/summary" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Python Client Example

```python
import requests

BASE_URL = "http://localhost:8000"

# 1. Register a new user
register_response = requests.post(
    f"{BASE_URL}/api/auth/register",
    json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "securepassword123"
    }
)
print("Registration:", register_response.json())

# 2. Login and get token
login_response = requests.post(
    f"{BASE_URL}/api/auth/login",
    json={
        "username": "testuser",
        "password": "securepassword123"
    }
)
token_data = login_response.json()
access_token = token_data["access_token"]
print("Login successful, token obtained")

# 3. Create an audit
audit_response = requests.post(
    f"{BASE_URL}/api/audits",
    headers={"Authorization": f"Bearer {access_token}"},
    json={
        "raw_input": "pragma solidity ^0.8.0;\n\ncontract Test { function test() public {} }",
        "target_name": "TestContract"
    }
)
audit = audit_response.json()
print(f"Audit created: {audit['id']}")
print(f"Report preview: {audit['full_markdown_report'][:200]}...")

# 4. List audits
list_response = requests.get(
    f"{BASE_URL}/api/audits?limit=10",
    headers={"Authorization": f"Bearer {access_token}"}
)
audits = list_response.json()
print(f"Found {len(audits)} audits")

# 5. Get audit details
detail_response = requests.get(
    f"{BASE_URL}/api/audits/{audit['id']}",
    headers={"Authorization": f"Bearer {access_token}"}
)
full_report = detail_response.json()
print(f"Full report has {len(full_report['functions'])} functions analyzed")
```

### Error Handling

The API uses standard HTTP status codes:

- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Missing or invalid authentication token
- `404 Not Found` - Resource not found
- `422 Unprocessable Entity` - Validation error
- `500 Internal Server Error` - Server error
- `501 Not Implemented` - Endpoint not yet implemented (during development)

Error responses follow this format:
```json
{
  "detail": "Error message describing what went wrong"
}
```

### Authentication Flow

1. **Register** a new user account (or use existing credentials)
2. **Login** to obtain an access token (JWT)
3. **Include the token** in all subsequent requests:
   ```
   Authorization: Bearer <your_access_token>
   ```
4. Tokens expire after a set period (configured by the security module). Re-authenticate when needed.

### Postman Collection

A complete Postman collection is included in the repository:
- **File:** `Auditor_AI_API.postman_collection.json`
- **Import:** Open Postman → Import → Select the JSON file
- **Environment Variable:** Set `base_url` to `http://localhost:8000`
- **Auto-token:** The Login request automatically saves the token to the `access_token` environment variable

The collection includes:
- ✅ All authentication endpoints
- ✅ All audit endpoints with example payloads
- ✅ Statistics endpoints
- ✅ Health check endpoint
- ✅ Pre-configured authorization headers

---
🗺️ Future Roadmap
This project is a strong foundation. Future improvements could include:

[ ] Full Contract AST Parsing: Move from function-based analysis to a full Abstract Syntax Tree traversal for deeper context understanding.

[ ] Support for Multiple Files: Allow users to upload an entire Hardhat or Foundry project for analysis.

[ ] Integration with Other LLMs: Add support for models from Gemini, Anthropic, etc.

[ ] CI/CD Integration: Create a GitHub Action that automatically runs the auditor on every pull request.

🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.
