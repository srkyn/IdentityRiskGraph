from __future__ import annotations

from dataclasses import asdict

import pandas as pd
import plotly.express as px
import streamlit as st


def apply_theme() -> None:
    st.set_page_config(page_title="IdentityRiskGraph", page_icon="IRG", layout="wide")
    st.markdown(
        """
        <style>
        :root { --bg:#07111f; --panel:#0d1b2f; --panel2:#10243d; --border:#1e3a5f; --text:#e5eefb; --muted:#92a4bd; --cyan:#5eead4; --rose:#fb7185; --amber:#f59e0b; --blue:#60a5fa; }
        .stApp { background: radial-gradient(circle at top left, rgba(94,234,212,.08), transparent 34%), #07111f; color: var(--text); }
        section[data-testid="stSidebar"] { background: #081523; border-right: 1px solid var(--border); }
        h1, h2, h3 { letter-spacing: 0; }
        .irg-title { display:flex; align-items:center; gap:14px; padding: 10px 0 4px; }
        .irg-mark { width:38px; height:38px; border-radius:8px; background: linear-gradient(135deg,#5eead4,#60a5fa); color:#06101d; display:grid; place-items:center; font-weight:900; }
        .irg-subtitle { color: var(--muted); margin-top:-8px; }
        .kpi-card { background: linear-gradient(180deg, rgba(16,36,61,.96), rgba(13,27,47,.96)); border:1px solid var(--border); border-radius:8px; padding:16px; min-height:108px; box-shadow: 0 10px 30px rgba(0,0,0,.18); }
        .kpi-label { color: var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
        .kpi-value { font-size:30px; font-weight:800; margin-top:8px; }
        .sev-Critical,.band-Critical { color:#fecdd3; background:rgba(244,63,94,.22); border:1px solid rgba(244,63,94,.4); padding:3px 8px; border-radius:999px; font-weight:700; }
        .sev-High,.band-High { color:#fed7aa; background:rgba(245,158,11,.20); border:1px solid rgba(245,158,11,.38); padding:3px 8px; border-radius:999px; font-weight:700; }
        .sev-Medium,.band-Medium { color:#bfdbfe; background:rgba(96,165,250,.18); border:1px solid rgba(96,165,250,.34); padding:3px 8px; border-radius:999px; font-weight:700; }
        .sev-Low,.band-Low { color:#bbf7d0; background:rgba(34,197,94,.16); border:1px solid rgba(34,197,94,.3); padding:3px 8px; border-radius:999px; font-weight:700; }
        div[data-testid="stDataFrame"] { border:1px solid var(--border); border-radius:8px; overflow:hidden; }
        .note-panel { background:#0d1b2f; border:1px solid var(--border); border-radius:8px; padding:14px; color:var(--muted); }
        </style>
        """,
        unsafe_allow_html=True,
    )


def header() -> None:
    st.markdown(
        """
        <div class="irg-title"><div class="irg-mark">IRG</div><div><h1>IdentityRiskGraph</h1><div class="irg-subtitle">Identity-first detection engineering for IAM and SOC investigations</div></div></div>
        """,
        unsafe_allow_html=True,
    )


def kpi(label: str, value: str | int) -> None:
    st.markdown(f'<div class="kpi-card"><div class="kpi-label">{label}</div><div class="kpi-value">{value}</div></div>', unsafe_allow_html=True)


def badge(value: str, prefix: str = "sev") -> str:
    return f'<span class="{prefix}-{value}">{value}</span>'


def detection_dataframe(findings) -> pd.DataFrame:
    rows = []
    for finding in findings:
        row = asdict(finding)
        row["evidence"] = str(row["evidence"])
        row["investigation_questions"] = " | ".join(row["investigation_questions"])
        rows.append(row)
    return pd.DataFrame(rows)


def bar_chart(df: pd.DataFrame, x: str, y: str, color: str | None = None, title: str = ""):
    if df.empty:
        st.info("No data for this chart.")
        return
    fig = px.bar(df, x=x, y=y, color=color, title=title, template="plotly_dark", color_discrete_sequence=["#5eead4", "#60a5fa", "#f59e0b", "#fb7185"])
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(7,17,31,.6)", font_color="#e5eefb")
    st.plotly_chart(fig, use_container_width=True)

