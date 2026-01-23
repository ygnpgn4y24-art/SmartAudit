import json
import streamlit as st

from src.audit_service import get_audit


def _get_current_user_id() -> int:
    """
    Temporary user resolution.

    NOTE for Member 2 (Auth):
    - Replace this with real user info from the auth layer, e.g. session or JWT.
    """

    return 1


def main() -> None:
    st.set_page_config(page_title="Audit Report Detail", layout="wide")
    st.title("🧾 Audit Report Detail")

    # Support both new and legacy Streamlit query params APIs
    try:
        query_params = st.query_params  # type: ignore[attr-defined]
    except Exception:
        query_params = st.experimental_get_query_params()

    audit_id = None
    if isinstance(query_params, dict):
        # experimental_get_query_params returns Dict[str, List[str]]
        raw = query_params.get("audit_id")
        if isinstance(raw, list) and raw:
            audit_id = raw[0]
        elif isinstance(raw, str):
            audit_id = raw
    else:
        # Newer st.query_params behaves like Mapping[str, str]
        audit_id = query_params.get("audit_id")

    audit_id_str = st.text_input("Audit ID", value=audit_id or "")

    if not audit_id_str:
        st.info("Provide an Audit ID in the URL or the input box above.")
        return
    try:
        audit_id_int = int(audit_id_str)
    except ValueError:
        st.error("Audit ID must be an integer.")
        return

    user_id = _get_current_user_id()
    audit = get_audit(audit_id_int, user_id=user_id)

    if audit is None:
        st.error("Audit not found or you don't have access to it.")
        return

    st.markdown(f"**Audit ID:** `{audit.id}`")
    st.markdown(f"**Contract:** `{audit.contract_name or '(unnamed)'}`")
    st.markdown(f"**Created At (UTC):** `{audit.created_at.isoformat()}`")
    st.markdown(f"**Severity Score:** `{audit.severity_score}`")
    st.markdown(f"**Vulnerabilities Count:** `{audit.vulnerabilities_count}`")
    st.markdown(f"**Analysis Duration (s):** `{audit.analysis_duration:.3f}`")

    with st.expander("Original Input (Solidity / Question)", expanded=False):
        st.code(audit.contract_code, language="solidity")

    st.subheader("Heuristic Checks")
    try:
        data = json.loads(audit.heuristic_results) if audit.heuristic_results else {}
        alerts = data.get("alerts", [])
        if not alerts:
            st.markdown("_No heuristic alerts._")
        else:
            for alert in alerts:
                st.markdown(alert)
    except Exception:
        st.code(audit.heuristic_results, language="json")

    st.subheader("Full AI-Powered Analysis")
    st.markdown(audit.ai_analysis)

    st.subheader("Vulnerabilities")
    if not audit.vulnerabilities:
        st.markdown("_No vulnerabilities parsed from the report._")
    else:
        for v in audit.vulnerabilities:
            st.markdown(f"### {v.name}")
            st.markdown(f"- **Severity:** `{v.severity}`")
            st.markdown(f"- **Function:** `{v.function_name}`")
            st.markdown(f"- **Line:** `{v.line_number}`")
            if v.description:
                st.markdown(f"- **Description:** {v.description}")
            if v.recommendation:
                st.markdown(f"- **Recommendation:** {v.recommendation}")

    st.subheader("Per-Function Breakdown (extra)")
    if not audit.functions:
        st.markdown("_No per-function breakdown available._")
        return
    for f in audit.functions:
        st.markdown(f"### Function `{f.get('function_name', 'Unknown')}`")
        with st.expander("Source Code", expanded=False):
            st.code(f.get("source_code", ""), language="solidity")
        with st.expander("AI Report", expanded=False):
            st.markdown(f.get("markdown_report", ""))


if __name__ == "__main__":
    main()

