import streamlit as st

from src.audit_service import list_audits_for_user


def _get_current_user_id() -> int:
    """
    Temporary user resolution.

    NOTE for Member 2 (Auth):
    - Replace this with real user info from the auth layer, e.g. session or JWT.
    """

    # Placeholder: single demo user
    return 1


def main() -> None:
    st.set_page_config(page_title="Audit History", layout="wide")
    st.title("📜 Audit History")
    st.markdown(
        "This page shows previously run audits. "
        "Authentication and multi-user separation will be added by the auth module."
    )

    user_id = _get_current_user_id()
    audits = list_audits_for_user(user_id=user_id, limit=100)

    if not audits:
        st.info("No audits have been recorded yet. Run an analysis from the main page first.")
        return

    rows = []
    for audit in audits:
        rows.append(
            {
                "Audit ID": audit.id,
                "Contract": audit.contract_name or "(unnamed)",
                "Created At (UTC)": audit.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "Vulns": audit.vulnerabilities_count,
                "Severity Score": audit.severity_score,
                "Duration (s)": round(audit.analysis_duration, 3),
            }
        )

    st.dataframe(rows, hide_index=True)

    st.markdown("---")
    st.subheader("Open Audit Detail")
    selected_id = st.text_input("Enter an Audit ID to open its details:", "")
    if st.button("Open Report") and selected_id:
        st.markdown(
            f"Open the report detail page and pass `audit_id={selected_id}` "
            "via the URL query parameters."
        )
        st.code(
            "Example URL:\n"
            "http://localhost:8501/report_detail?audit_id="
            + selected_id,
            language="text",
        )


if __name__ == "__main__":
    main()

