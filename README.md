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
Once the knowledge base is built, you can start the web application:

streamlit run app.py
The application will open in your web browser.

🛠️ Technology Stack
Component	Technology
Web Framework	Streamlit
AI / RAG	LangChain, OpenAI API
Vector Store	FAISS (Facebook AI Similarity Search)
Code Parsing	solidity-parser
Environment	Python, python-dotenv

Export to Sheets
🗺️ Future Roadmap
This project is a strong foundation. Future improvements could include:

[ ] Full Contract AST Parsing: Move from function-based analysis to a full Abstract Syntax Tree traversal for deeper context understanding.

[ ] Support for Multiple Files: Allow users to upload an entire Hardhat or Foundry project for analysis.

[ ] Integration with Other LLMs: Add support for models from Gemini, Anthropic, etc.

[ ] CI/CD Integration: Create a GitHub Action that automatically runs the auditor on every pull request.

🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.