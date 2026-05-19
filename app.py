from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from src.aws_iam_detections import cloudtrail_findings_to_detection_findings, detect_aws_iam_risks
from src.cloudtrail_parser import load_cloudtrail, normalize_cloudtrail_events
from src.config import DATA_DIR
from src.detections import run_detections
from src.exports import findings_to_dataframe, findings_to_json, risky_identities_dataframe, user_report_markdown
from src.graph_builder import build_identity_graph, render_pyvis
from src.ingest import load_all_data
from src.normalizer import normalize_events
from src.permission_resolver import resolve_all_access
from src.risk_engine import score_all_users
from src.rule_loader import load_yaml_rules
from src.splunk_export import findings_to_splunk_json
from src.ui_components import apply_theme, badge, bar_chart, header, kpi


@st.cache_data
def load_pipeline() -> dict:
    data = load_all_data()
    access = resolve_all_access(data["users"], data["groups"], data["roles"])
    normalized = normalize_events(data["events"], data["resources"])
    cloudtrail_path = DATA_DIR / "cloudtrail" / "sample_cloudtrail_iam_events.json"
    cloudtrail_events = load_cloudtrail(cloudtrail_path)
    cloudtrail_findings = detect_aws_iam_risks(cloudtrail_events)
    cloudtrail_normalized = normalize_cloudtrail_events(cloudtrail_events)
    yaml_rules = load_yaml_rules(DATA_DIR.parent / "rules" / "cloudtrail_iam_rules.yaml")
    enterprise_findings = run_detections(data["users"], data["events"], data["devices"], data["resources"], data["account_changes"], access)
    cloudtrail_identity_findings = cloudtrail_findings_to_detection_findings(cloudtrail_findings, data["users"])
    findings = enterprise_findings + cloudtrail_identity_findings
    risks = score_all_users(data["users"], access, findings, data["events"], data["devices"])
    return {
        **data,
        "access": access,
        "normalized_events": normalized + cloudtrail_normalized,
        "findings": findings,
        "enterprise_findings": enterprise_findings,
        "cloudtrail_path": cloudtrail_path,
        "cloudtrail_events": cloudtrail_events,
        "cloudtrail_findings": cloudtrail_findings,
        "yaml_rules": yaml_rules,
        "risks": risks,
    }


def main() -> None:
    apply_theme()
    data = load_pipeline()
    header()

    if "finding_status" not in st.session_state:
        st.session_state.finding_status = {}
    if "analyst_notes" not in st.session_state:
        st.session_state.analyst_notes = {}

    st.sidebar.markdown(
        """
        **Demo Flow**

        1. Start with **CloudTrail IAM Detections**.
        2. Open a high-severity finding.
        3. Review **Risky Identities**.
        4. Investigate Caleb Stone or David User.
        5. Use **Identity Graph** to inspect access paths.
        """,
    )

    page = st.sidebar.radio(
        "Workspace",
        [
            "Executive Overview",
            "Risky Identities",
            "Detection Findings",
            "CloudTrail IAM Detections",
            "Identity Graph",
            "User Investigation",
            "Raw Events",
            "Export / Reports",
            "About / Methodology",
        ],
    )

    if page == "Executive Overview":
        executive_overview(data)
    elif page == "Risky Identities":
        risky_identities(data)
    elif page == "Detection Findings":
        detection_findings(data)
    elif page == "CloudTrail IAM Detections":
        cloudtrail_iam_detections(data)
    elif page == "Identity Graph":
        identity_graph(data)
    elif page == "User Investigation":
        user_investigation(data)
    elif page == "Raw Events":
        raw_events(data)
    elif page == "Export / Reports":
        exports_page(data)
    else:
        methodology_page()


def executive_overview(data: dict) -> None:
    st.subheader("Executive Overview")
    st.caption("Identity risk, detection volume, and the highest-signal IAM conditions from the simulated environment.")
    risks = data["risks"]
    findings = data["findings"]
    cols = st.columns(8)
    metrics = [
        ("Total Users", len(data["users"])),
        ("Critical Identities", sum(1 for risk in risks.values() if risk.band == "Critical")),
        ("High Risk", sum(1 for risk in risks.values() if risk.band == "High")),
        ("Total Detections", len(findings)),
        ("Toxic Combos", sum(1 for f in findings if f.detection_id == "toxic_permission_combination")),
        ("Dormant Access", sum(1 for f in findings if f.detection_id == "dormant_account_access")),
        ("Untrusted Admin", sum(1 for f in findings if f.detection_id == "privileged_untrusted_device")),
        ("Svc Logins", sum(1 for f in findings if f.detection_id == "service_account_interactive_login")),
    ]
    for col, (label, value) in zip(cols, metrics):
        with col:
            kpi(label, value)

    users_by_id = {user.user_id: user for user in data["users"]}
    dept_rows = []
    for user_id, risk in risks.items():
        dept_rows.append({"department": users_by_id[user_id].department, "risk_score": risk.score})
    dept_df = pd.DataFrame(dept_rows).groupby("department", as_index=False)["risk_score"].mean().sort_values("risk_score", ascending=False)
    finding_df = pd.DataFrame([{"type": f.detection_name, "severity": f.severity} for f in findings])
    col1, col2 = st.columns(2)
    with col1:
        bar_chart(dept_df, "department", "risk_score", title="Average Risk By Department")
    with col2:
        counts = finding_df.groupby(["type"], as_index=False).size().sort_values("size", ascending=False).head(10) if not finding_df.empty else finding_df
        bar_chart(counts, "type", "size", title="Top Detection Types")

    trend = pd.DataFrame([{"date": f.timestamp[:10], "severity": f.severity, "count": 1} for f in findings])
    if not trend.empty:
        trend = trend.groupby(["date", "severity"], as_index=False)["count"].sum()
        st.line_chart(trend.pivot(index="date", columns="severity", values="count").fillna(0), use_container_width=True)


def risky_identities(data: dict) -> None:
    st.subheader("Risky Identities")
    st.caption("Prioritized identity risk scores with the top reason, inherited access, and role context.")
    df = risky_identities_dataframe(data["users"], data["risks"], data["access"])
    st.dataframe(_title_columns(df), use_container_width=True, hide_index=True)


def detection_findings(data: dict) -> None:
    st.subheader("Detection Findings")
    st.caption("Combined enterprise IAM detections and CloudTrail IAM findings that match simulated identities.")
    users_by_id = {user.user_id: user for user in data["users"]}
    findings = data["findings"]
    c1, c2, c3, c4 = st.columns(4)
    severity = c1.multiselect("Severity", sorted({f.severity for f in findings}), default=sorted({f.severity for f in findings}))
    detection_type = c2.multiselect("Detection Type", sorted({f.detection_name for f in findings}))
    user_type = c3.multiselect("User Type", sorted({user.user_type for user in data["users"]}))
    department = c4.multiselect("Department", sorted({user.department for user in data["users"]}))
    mitre = st.multiselect("MITRE Technique", sorted({f.mitre_technique for f in findings}))

    filtered = []
    for finding in findings:
        user = users_by_id[finding.user_id]
        if severity and finding.severity not in severity:
            continue
        if detection_type and finding.detection_name not in detection_type:
            continue
        if user_type and user.user_type not in user_type:
            continue
        if department and user.department not in department:
            continue
        if mitre and finding.mitre_technique not in mitre:
            continue
        filtered.append(finding)

    for finding in filtered:
        user = users_by_id[finding.user_id]
        status_key = f"{finding.detection_id}:{finding.user_id}:{finding.timestamp}"
        with st.expander(f"{finding.severity} | {finding.detection_name} | {user.display_name} | {finding.timestamp}", expanded=finding.severity == "Critical"):
            st.markdown(badge(finding.severity), unsafe_allow_html=True)
            st.write(finding.reason)
            st.json(finding.evidence)
            st.write(f"**Identity context:** {user.department} / {user.job_title} / {user.user_type}")
            st.write(f"**Recommended action:** {finding.recommended_action}")
            st.write(f"**MITRE:** {finding.mitre_technique}")
            st.write("**Analyst questions:**")
            for question in finding.investigation_questions:
                st.write(f"- {question}")
            st.session_state.finding_status[status_key] = st.selectbox(
                "Finding status",
                ["New", "Investigating", "Benign", "Needs Review", "Escalated"],
                key=f"status-{status_key}",
                index=["New", "Investigating", "Benign", "Needs Review", "Escalated"].index(st.session_state.finding_status.get(status_key, "New")),
            )


def cloudtrail_iam_detections(data: dict) -> None:
    findings = data["cloudtrail_findings"]
    st.subheader("CloudTrail IAM Detections")
    st.caption("Raw CloudTrail-style IAM events are parsed first, alerted in the terminal, then normalized into dashboard-ready findings.")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi("Loaded File", "Sample IAM Events")
    with c2:
        kpi("CloudTrail Events", len(data["cloudtrail_events"]))
    with c3:
        kpi("Risky IAM Events", len(findings))
    with c4:
        kpi("YAML Rules", len(data["yaml_rules"]))

    table = pd.DataFrame([asdict(finding) for finding in findings])
    if table.empty:
        st.success("No risky CloudTrail IAM detections found.")
        return

    c1, c2, c3, c4 = st.columns(4)
    severities = c1.multiselect("Severity", sorted(table["severity"].unique()), default=sorted(table["severity"].unique()))
    event_names = c2.multiselect("Event Name", sorted(table["event_name"].unique()))
    actors = c3.multiselect("Actor", sorted(table["actor"].unique()))
    targets = c4.multiselect("Target Identity", sorted(table["target_identity"].unique()))

    filtered = table.copy()
    if severities:
        filtered = filtered[filtered["severity"].isin(severities)]
    if event_names:
        filtered = filtered[filtered["event_name"].isin(event_names)]
    if actors:
        filtered = filtered[filtered["actor"].isin(actors)]
    if targets:
        filtered = filtered[filtered["target_identity"].isin(targets)]

    display = filtered[["severity", "detection_name", "event_name", "actor", "target_identity", "source_ip", "timestamp", "risk_score_delta"]].rename(columns={
        "severity": "Severity",
        "detection_name": "Detection",
        "event_name": "CloudTrail Event",
        "actor": "Actor",
        "target_identity": "Target Identity",
        "source_ip": "Source IP",
        "timestamp": "Timestamp",
        "risk_score_delta": "Risk Delta",
    })
    st.dataframe(
        display,
        use_container_width=True,
        hide_index=True,
    )

    for row in filtered.to_dict(orient="records"):
        with st.expander(f"{row['severity']} | {row['event_name']} | {row['target_identity']} | {row['timestamp']}", expanded=row["severity"] == "Critical"):
            st.markdown(badge(row["severity"]), unsafe_allow_html=True)
            st.write(row["reason"])
            st.write(f"**Actor:** {row['actor']}")
            st.write(f"**Source IP:** {row['source_ip']}")
            st.write(f"**MITRE:** {row['mitre_technique']}")
            st.write(f"**Recommended action:** {row['recommended_action']}")
            st.json(row["evidence"])


def identity_graph(data: dict) -> None:
    st.subheader("Identity Graph")
    st.caption("Relationship graph for users, nested groups, roles, permissions, and sensitive resources.")
    user_options = {"All identities": None} | {user.display_name: user.user_id for user in data["users"]}
    selected = st.selectbox("Graph scope", list(user_options.keys()))
    critical_only = st.checkbox("Show critical / sensitive paths only", value=True)
    graph = build_identity_graph(data["users"], data["groups"], data["roles"], data["permissions"], data["resources"], data["access"], user_options[selected], critical_only)
    html_path = render_pyvis(graph)
    components.html(html_path.read_text(encoding="utf-8"), height=760, scrolling=True)


def user_investigation(data: dict) -> None:
    st.subheader("User Investigation")
    st.caption("Analyst case view: profile, risk factors, access paths, recent activity, findings, and notes.")
    users_by_name = {user.display_name: user for user in data["users"]}
    names = sorted(users_by_name)
    default_index = names.index("Caleb Stone") if "Caleb Stone" in names else 0
    selected = st.selectbox("Select identity", names, index=default_index)
    user = users_by_name[selected]
    risk = data["risks"][user.user_id]
    access = data["access"][user.user_id]
    user_findings = [finding for finding in data["findings"] if finding.user_id == user.user_id]
    user_events = [event for event in data["events"] if event.user_id == user.user_id]
    user_changes = [change for change in data["account_changes"] if change.target_user_id == user.user_id or change.actor_user_id == user.user_id]

    c1, c2, c3, c4 = st.columns(4)
    with c1: kpi("Risk Score", risk.score)
    with c2: kpi("Risk Band", risk.band)
    with c3: kpi("Sensitive Permissions", len(access.sensitive_permissions))
    with c4: kpi("Detections", len(user_findings))

    st.markdown(f"### Case: {user.display_name}")
    st.write(f"**{user.job_title}** in **{user.department}** | `{user.user_type}` | Status: `{user.status}`")
    st.info("Demo tip: Caleb Stone shows contractor risk plus CloudTrail IAM findings. David User shows nested group privilege inheritance.")

    st.subheader("Risk Breakdown")
    st.dataframe(pd.DataFrame([asdict(factor) for factor in risk.factors]), use_container_width=True, hide_index=True)

    st.subheader("Effective Permissions")
    st.dataframe(pd.DataFrame({
        "direct_roles": [", ".join(sorted(access.direct_roles))],
        "inherited_roles": [", ".join(sorted(access.inherited_roles))],
        "sensitive_permissions": [", ".join(sorted(access.sensitive_permissions))],
        "boundary_limited_permissions": [", ".join(sorted(access.boundary_limited_permissions))],
    }), use_container_width=True, hide_index=True)

    st.subheader("Privilege Paths")
    path_rows = [{"permission": path.permission, "role_id": path.role_id, "nested_depth": path.nested_depth, "path": " -> ".join(path.path)} for path in access.paths if path.permission in access.sensitive_permissions]
    st.dataframe(pd.DataFrame(path_rows), use_container_width=True, hide_index=True)

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Recent Events")
        st.dataframe(pd.DataFrame([asdict(event) for event in user_events]).sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)
    with c2:
        st.subheader("Account Changes")
        st.dataframe(pd.DataFrame([asdict(change) for change in user_changes]), use_container_width=True, hide_index=True)

    st.subheader("Detection Findings")
    for finding in user_findings:
        with st.expander(f"{finding.severity}: {finding.detection_name}"):
            st.write(finding.reason)
            st.json(finding.evidence)

    st.subheader("Analyst Notes")
    st.session_state.analyst_notes[user.user_id] = st.text_area("Notes", value=st.session_state.analyst_notes.get(user.user_id, ""), height=160)


def raw_events(data: dict) -> None:
    st.subheader("Raw Events")
    st.caption("Normalized OCSF-inspired events beside the original simulated enterprise events.")
    tab1, tab2 = st.tabs(["Normalized Events", "Raw JSON Events"])
    with tab1:
        st.dataframe(pd.DataFrame([asdict(event) for event in data["normalized_events"]]), use_container_width=True, hide_index=True)
    with tab2:
        st.dataframe(pd.DataFrame([asdict(event) for event in data["events"]]), use_container_width=True, hide_index=True)


def exports_page(data: dict) -> None:
    st.subheader("Export / Reports")
    st.write("Export investigation artifacts for ticketing, reporting, or portfolio review.")
    findings_df = findings_to_dataframe(data["findings"])
    risky_df = risky_identities_dataframe(data["users"], data["risks"], data["access"])
    st.download_button("Download all findings CSV", findings_df.to_csv(index=False), "identityriskgraph_findings.csv", "text/csv")
    st.download_button("Download all findings JSON", findings_to_json(data["findings"]), "identityriskgraph_findings.json", "application/json")
    st.download_button("Download Splunk-friendly JSON", findings_to_splunk_json(data["findings"] + data["cloudtrail_findings"]), "identityriskgraph_splunk_events.json", "application/json")
    st.download_button("Download risky identities CSV", risky_df.to_csv(index=False), "identityriskgraph_risky_identities.csv", "text/csv")

    users_by_name = {user.display_name: user for user in data["users"]}
    selected = st.selectbox("User report", sorted(users_by_name))
    user = users_by_name[selected]
    report = user_report_markdown(
        user,
        data["risks"][user.user_id],
        data["access"][user.user_id],
        [finding for finding in data["findings"] if finding.user_id == user.user_id],
    )
    st.download_button("Download user investigation Markdown", report, f"{user.user_id}_investigation.md", "text/markdown")
    st.markdown(report)


def methodology_page() -> None:
    st.subheader("About / Methodology")
    st.markdown(
        """
        IdentityRiskGraph is a simulated defensive IAM/SOC analyst tool. It does not connect to real cloud APIs, collect credentials, or use tenant data.

        The app normalizes JSON telemetry into an OCSF-inspired internal schema, resolves effective access through direct roles and nested groups, evaluates deterministic detection rules, assigns explainable risk, and presents investigation-ready identity context.

        The guiding question is: is this event weird for this identity, in this role, from this device, at this time, with this access path?
        """
    )


def _title_columns(df: pd.DataFrame) -> pd.DataFrame:
    return df.rename(columns={column: column.replace("_", " ").title() for column in df.columns})


if __name__ == "__main__":
    main()
