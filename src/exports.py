from __future__ import annotations

import json
from dataclasses import asdict

import pandas as pd

from src.models import DetectionFinding, EffectiveAccess, RiskProfile, User


def findings_to_dataframe(findings: list[DetectionFinding]) -> pd.DataFrame:
    return pd.DataFrame([asdict(finding) for finding in findings])


def findings_to_json(findings: list[DetectionFinding]) -> str:
    return json.dumps([asdict(finding) for finding in findings], indent=2, default=str)


def risky_identities_dataframe(users: list[User], risk_profiles: dict[str, RiskProfile], access_by_user: dict[str, EffectiveAccess]) -> pd.DataFrame:
    rows = []
    for user in users:
        risk = risk_profiles[user.user_id]
        access = access_by_user[user.user_id]
        rows.append({
            "user": user.display_name,
            "email": user.email,
            "department": user.department,
            "job_title": user.job_title,
            "user_type": user.user_type,
            "risk_score": risk.score,
            "risk_band": risk.band,
            "top_reason": risk.top_reason,
            "direct_roles": ", ".join(sorted(access.direct_roles)),
            "inherited_roles": ", ".join(sorted(access.inherited_roles)),
            "last_login": user.last_login,
        })
    return pd.DataFrame(rows).sort_values("risk_score", ascending=False)


def user_report_markdown(user: User, risk: RiskProfile, access: EffectiveAccess, findings: list[DetectionFinding]) -> str:
    factors = "\n".join(f"- {factor.factor}: +{factor.points} - {factor.reason}" for factor in risk.factors)
    paths = "\n".join(f"- {' -> '.join(path.path)}" for path in access.paths if path.permission in access.sensitive_permissions) or "- No sensitive paths"
    finding_lines = "\n".join(f"- {finding.severity}: {finding.detection_name} - {finding.reason}" for finding in findings) or "- No detections"
    return f"""# Identity Investigation Report: {user.display_name}

**Risk score:** {risk.score} ({risk.band})
**Department:** {user.department}
**Job title:** {user.job_title}
**User type:** {user.user_type}
**Status:** {user.status}

## Risk Factors
{factors}

## Sensitive Permission Paths
{paths}

## Detection Findings
{finding_lines}

## Recommended Analyst Actions
- Validate the access path with the user's manager and access owner.
- Review recent role and group changes.
- Confirm device trust, geography, and business justification.
- Escalate if access was not approved or cannot be explained.
"""

