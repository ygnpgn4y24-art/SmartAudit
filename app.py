import streamlit as st
from src.logic import initialize_qa_chain, run_heuristic_checks, analyze_code_with_ai
from src.logger_config import logger

# --- User Interface ---
st.set_page_config(page_title="Auditor AI", layout="wide")

# --- Sidebar ---
with st.sidebar:
    st.title("About Auditor AI")
    st.markdown("""
    **Auditor AI** is a proof-of-concept tool that leverages Large Language Models (LLMs) and Retrieval-Augmented Generation (RAG) to analyze Solidity smart contracts for potential security vulnerabilities.
    
    **How it works:**
    1.  It runs a quick heuristic check for common issues.
    2.  It uses a specialized knowledge base built from ConsenSys's best practices.
    3.  An LLM analyzes your code against this knowledge base to provide structured insights with severity levels.
    
    **Disclaimer:** This is an educational tool and should not be used as a replacement for a professional security audit.
    """)
    st.markdown("---")
    st.subheader("Example Queries")
    
    example_1 = st.button("Analyze for Reentrancy risks")
    example_2 = st.button("Check `tx.origin` usage")
    example_3 = st.button("Explain risks of outdated Solidity pragma")

# --- Main Page ---
st.title("🤖 Auditor: AI Smart Contract Security Assistant")
st.markdown("Enter a snippet of your Solidity smart contract or ask a security-related question below.")

qa_chain = initialize_qa_chain()

if qa_chain:
    with st.form("audit_form"):
        if example_1:
            initial_input = "What is a reentrancy attack and how can I prevent it in my code?"
        elif example_2:
            initial_input = "function withdraw(uint amount) public { require(balances[msg.sender] >= amount); (bool success, ) = msg.sender.call{value: amount}(\"\"); require(success, \"Failed to send Ether\"); balances[msg.sender] -= amount; }"
        elif example_3:
            initial_input = "pragma solidity ^0.5.0;"
        else:
            initial_input = ""
            
        user_input = st.text_area("Your Solidity Code or Security Question:", value=initial_input, height=250, placeholder="function transfer(address to, uint265 amount) public { ... }")
        submitted = st.form_submit_button("Analyze Now")

    if submitted and user_input:
        logger.info(f"New submission received. Input length: {len(user_input)}.")
        st.subheader("Heuristic Analysis")
        heuristic_alerts = run_heuristic_checks(user_input)
        for alert in heuristic_alerts:
            st.markdown(alert)
        
        st.markdown("---")
        
        with st.spinner("Auditor is performing deep, context-aware analysis..."):
            try:
                analysis_result = analyze_code_with_ai(qa_chain, user_input)
                st.subheader("Deep AI-Powered Analysis")
                st.markdown(analysis_result)
                
            except Exception as e:
                logger.critical(f"An unhandled exception occurred in the main analysis block: {e}", exc_info=True)
                st.error("A critical error occurred. The incident has been logged. Please check `auditor.log` for more details.")
else:
    st.warning("The Auditor engine could not be initialized. Please check the console for errors and see `auditor.log`.")

