from __future__ import annotations

from collections import defaultdict

from src.models import DetectionFinding, Device, EffectiveAccess, Event, RiskFactor, RiskProfile, User
from src.utils import clamp, risk_band


def _add(factors: list[RiskFactor], factor: str, points: int, reason: str, evidence: str) -> None:
    if points > 0:
        factors.append(RiskFactor(factor, points, reason, evidence))


def score_user(
    user: User,
    access: EffectiveAccess,
    detections: list[DetectionFinding],
    events: list[Event],
    devices_by_id: dict[str, Device],
) -> RiskProfile:
    factors: list[RiskFactor] = []
    baseline = 5
    if user.user_type.lower() == "service_account":
        baseline += 8
    if user.user_type.lower() == "contractor":
        baseline += 7
    if "break_glass" in user.risk_tags:
        baseline += 12
    if user.status != "active":
        baseline += 10
    _add(factors, "Identity baseline", baseline, "Static identity context raises baseline risk.", f"{user.user_type}, {user.status}, tags={user.risk_tags}")

    _add(factors, "Privilege level", access.max_privilege_level * 3, "Effective roles create privileged blast radius.", f"max_privilege_level={access.max_privilege_level}")
    _add(factors, "Inherited access", min(12, len(access.inherited_roles) * 3), "Inherited roles are harder to review than direct assignment.", f"inherited_roles={sorted(access.inherited_roles)}")
    _add(factors, "Nested group depth", min(15, access.nested_group_depth * 5), "Deep group nesting obscures privilege paths.", f"nested_depth={access.nested_group_depth}")
    _add(factors, "Sensitive permissions", min(18, len(access.sensitive_permissions) * 2), "Sensitive permissions can affect identities or regulated data.", f"count={len(access.sensitive_permissions)}")

    user_events = [event for event in events if event.user_id == user.user_id]
    untrusted = [
        event for event in user_events
        if event.device_id in devices_by_id and (not devices_by_id[event.device_id].managed or not devices_by_id[event.device_id].compliant)
    ]
    _add(factors, "Device trust", 12 if untrusted and access.max_privilege_level >= 7 else 0, "Privileged activity used an unmanaged or noncompliant endpoint.", f"events={len(untrusted)}")
    _add(factors, "Sensitive resource access", min(10, sum(1 for event in user_events if event.action in {"export_records", "download_bulk", "read_phi", "export_payroll"})), "Recent telemetry includes sensitive resource activity.", "sensitive events counted")

    for finding in detections:
        _add(factors, f"Detection: {finding.detection_name}", finding.risk_score_delta, finding.reason, str(finding.evidence)[:240])

    total = clamp(sum(factor.points for factor in factors))
    top_reason = max(factors, key=lambda factor: factor.points).reason if factors else "No elevated risk factors."
    return RiskProfile(user.user_id, total, risk_band(total), top_reason, factors)


def score_all_users(
    users: list[User],
    access_by_user: dict[str, EffectiveAccess],
    detections: list[DetectionFinding],
    events: list[Event],
    devices: list[Device],
) -> dict[str, RiskProfile]:
    findings_by_user = defaultdict(list)
    for finding in detections:
        findings_by_user[finding.user_id].append(finding)
    devices_by_id = {device.device_id: device for device in devices}
    return {
        user.user_id: score_user(user, access_by_user[user.user_id], findings_by_user[user.user_id], events, devices_by_id)
        for user in users
    }

