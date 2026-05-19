from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from src.mitre import MITRE_TECHNIQUES
from src.models import AccountChange, DetectionFinding, Device, EffectiveAccess, Event, Resource, User
from src.utils import days_between, parse_time, velocity_mph


RECOMMENDED_ACTIONS = {
    "toxic_permission_combination": "Open an access review for this identity, separate IAM administration from data export capability, and validate compensating controls.",
    "nested_group_privilege_escalation": "Trace the full group path with the group owners, remove legacy nesting if unnecessary, and require explicit approval for privileged inheritance.",
    "dormant_account_access": "Disable the account pending owner validation, review recent activity, and confirm whether reactivation was approved.",
    "privileged_untrusted_device": "Challenge the session, verify endpoint compliance, and require privileged access from a managed device.",
    "impossible_travel": "Validate MFA and session history, compare with travel records or VPN use, and reset credentials if unexplained.",
    "role_change_sensitive_access": "Review the change ticket and approver, confirm the sensitive access was expected, and revoke the new grant if unjustified.",
    "service_account_interactive_login": "Disable interactive sign-in for the service account, rotate credentials, and move automation to managed workload identity where possible.",
    "contractor_privileged_access": "Confirm contract scope and data-owner approval, add an expiration date, and reduce access to least privilege.",
    "break_glass_usage": "Start emergency-access review, confirm incident authorization, rotate credentials, and document the session.",
    "boundary_violation_attempt": "Review why the blocked action was attempted, confirm the boundary is correct, and look for follow-on success through another path.",
    "excessive_inherited_permissions": "Run an inherited-access review, identify the group owner, and replace broad inherited access with targeted assignment.",
    "stale_privileged_assignment": "Remove or re-approve the stale privileged assignment and document the business owner.",
    "data_exfiltration_pattern": "Contain export capability, validate business justification, preserve logs, and notify the data owner.",
    "denied_then_success": "Correlate denied attempts with recent access changes and confirm whether successful access was authorized.",
    "admin_assigned_by_unusual_actor": "Validate the actor's authority to grant admin access and review adjacent changes from the same session.",
}


def _finding(key: str, name: str, severity: str, user_id: str, timestamp: str, reason: str, evidence: dict, delta: int) -> DetectionFinding:
    return DetectionFinding(
        detection_id=key,
        detection_name=name,
        severity=severity,
        user_id=user_id,
        entity_type="identity",
        timestamp=timestamp,
        reason=reason,
        evidence=evidence,
        risk_score_delta=delta,
        mitre_technique=MITRE_TECHNIQUES[key],
        recommended_action=RECOMMENDED_ACTIONS[key],
        investigation_questions=[
            "Is this behavior normal for this identity's role and department?",
            "Was the access approved through a documented request?",
            "Did the device, location, and access path match the user's baseline?",
        ],
    )


def run_detections(
    users: list[User],
    events: list[Event],
    devices: list[Device],
    resources: list[Resource],
    changes: list[AccountChange],
    access_by_user: dict[str, EffectiveAccess],
) -> list[DetectionFinding]:
    users_by_id = {user.user_id: user for user in users}
    devices_by_id = {device.device_id: device for device in devices}
    resources_by_id = {resource.resource_id: resource for resource in resources}
    findings: list[DetectionFinding] = []
    login_events = sorted([event for event in events if event.event_type == "login" and event.result == "success"], key=lambda event: event.timestamp)

    for user in users:
        access = access_by_user[user.user_id]
        perms = access.permissions
        sensitive_exports = {p for p in perms if "export" in p or "download" in p}
        admin_perms = {p for p in perms if "admin" in p or "delete_user" in p or "assign_role" in p}

        if admin_perms and sensitive_exports:
            findings.append(_finding(
                "toxic_permission_combination",
                "Toxic Permission Combination",
                "High",
                user.user_id,
                user.last_login,
                "Identity can administer access and perform sensitive export actions.",
                {"admin_permissions": sorted(admin_perms), "export_permissions": sorted(sensitive_exports)},
                20,
            ))

        if access.max_privilege_level >= 8 and access.nested_group_depth >= 2:
            risky_paths = [" -> ".join(path.path) for path in access.paths if path.nested_depth >= 2 and path.permission in access.sensitive_permissions][:5]
            findings.append(_finding(
                "nested_group_privilege_escalation",
                "Nested Group Privilege Escalation",
                "Critical",
                user.user_id,
                user.last_login,
                "Privileged role is inherited through two or more group hops.",
                {"nested_depth": access.nested_group_depth, "paths": risky_paths},
                30,
            ))

        if user.user_type.lower() == "contractor" and (access.max_privilege_level >= 6 or len(access.sensitive_permissions) >= 2):
            findings.append(_finding(
                "contractor_privileged_access",
                "Contractor With Privileged Access",
                "High",
                user.user_id,
                user.last_login,
                "Contractor account has privileged or sensitive effective permissions.",
                {"privilege_level": access.max_privilege_level, "sensitive_permissions": sorted(access.sensitive_permissions)},
                22,
            ))

        inherited_sensitive = [path for path in access.paths if path.inherited and path.permission in access.sensitive_permissions]
        if len({path.permission for path in inherited_sensitive}) >= 8:
            findings.append(_finding(
                "excessive_inherited_permissions",
                "Excessive Inherited Permissions",
                "Medium",
                user.user_id,
                user.last_login,
                "Identity receives many sensitive permissions through group inheritance.",
                {"count": len({path.permission for path in inherited_sensitive}), "sample_paths": [" -> ".join(p.path) for p in inherited_sensitive[:5]]},
                14,
            ))

        if access.max_privilege_level >= 8 and "stale_privileged_assignment" in user.risk_tags:
            findings.append(_finding(
                "stale_privileged_assignment",
                "Stale Privileged Assignment",
                "Medium",
                user.user_id,
                user.last_login,
                "Privileged assignment appears unused or stale based on account context.",
                {"direct_roles": sorted(access.direct_roles), "inherited_roles": sorted(access.inherited_roles)},
                12,
            ))

    events_by_user = defaultdict(list)
    for event in sorted(events, key=lambda event: event.timestamp):
        events_by_user[event.user_id].append(event)

    for user_id, user_events in events_by_user.items():
        user = users_by_id.get(user_id)
        if not user:
            continue
        access = access_by_user[user_id]
        for event in user_events:
            device = devices_by_id.get(event.device_id)
            resource = resources_by_id.get(event.resource)
            if event.result == "success" and days_between(user.last_login, event.timestamp) >= 45 and ("dormant" in user.risk_tags or user.status != "active"):
                findings.append(_finding(
                    "dormant_account_access",
                    "Dormant Account Access",
                    "High",
                    user_id,
                    event.timestamp,
                    "Dormant or inactive identity was used successfully after a long gap.",
                    {"last_login_profile": user.last_login, "event": event.raw_message},
                    20,
                ))
            if access.max_privilege_level >= 7 and event.result == "success" and device and (not device.managed or not device.compliant):
                findings.append(_finding(
                    "privileged_untrusted_device",
                    "Privileged Access From Untrusted Device",
                    "High",
                    user_id,
                    event.timestamp,
                    "Privileged identity performed activity from unmanaged or noncompliant device.",
                    {"device": device.hostname, "managed": device.managed, "compliant": device.compliant, "action": event.action},
                    20,
                ))
            if user.user_type.lower() == "service_account" and event.event_type == "login" and event.result == "success":
                findings.append(_finding(
                    "service_account_interactive_login",
                    "Service Account Interactive Login",
                    "Critical",
                    user_id,
                    event.timestamp,
                    "Service account performed an interactive login.",
                    {"device_id": event.device_id, "message": event.raw_message},
                    30,
                ))
            if "break_glass" in user.risk_tags and event.event_type == "login" and event.result == "success":
                findings.append(_finding(
                    "break_glass_usage",
                    "Break-Glass Account Usage",
                    "Critical",
                    user_id,
                    event.timestamp,
                    "Break-glass account was used outside a documented emergency event in the sample data.",
                    {"source_ip": event.source_ip, "geo": event.geo},
                    32,
                ))
            if event.result in {"denied", "failure"} and event.action in access.boundary_limited_permissions:
                findings.append(_finding(
                    "boundary_violation_attempt",
                    "Permission Boundary Violation Attempt",
                    "Medium",
                    user_id,
                    event.timestamp,
                    "Identity attempted an action limited by a permissions boundary.",
                    {"attempted_action": event.action, "boundary_limited_permissions": sorted(access.boundary_limited_permissions)},
                    12,
                ))
            if resource and resource.sensitivity == "Restricted" and event.action in {"export_records", "download_bulk", "export_payroll"}:
                same_day = [
                    e for e in user_events
                    if e.resource == event.resource and e.action == event.action and abs((parse_time(e.timestamp) - parse_time(event.timestamp)).total_seconds()) < 7200
                ]
                if len(same_day) >= 3:
                    findings.append(_finding(
                        "data_exfiltration_pattern",
                        "Data Exfiltration Pattern",
                        "Critical",
                        user_id,
                        event.timestamp,
                        "Repeated sensitive export activity against a restricted resource.",
                        {"resource": resource.name, "export_count_2h": len(same_day)},
                        30,
                    ))
                    break

    for idx, first in enumerate(login_events):
        for second in login_events[idx + 1:]:
            if second.user_id != first.user_id:
                continue
            hours = (parse_time(second.timestamp) - parse_time(first.timestamp)).total_seconds() / 3600
            if hours > 8:
                break
            speed = velocity_mph(first.timestamp, first.geo, second.timestamp, second.geo)
            if speed > 550:
                findings.append(_finding(
                    "impossible_travel",
                    "Impossible Travel",
                    "High",
                    first.user_id,
                    second.timestamp,
                    "Successful logins require unrealistic travel velocity.",
                    {"from": first.geo, "to": second.geo, "hours": round(hours, 2), "mph": round(speed)},
                    22,
                ))
                break

    changes_by_target = defaultdict(list)
    for change in changes:
        changes_by_target[change.target_user_id].append(change)
        actor = users_by_id.get(change.actor_user_id)
        if change.change_type == "role_granted" and change.details.get("privileged") and actor and "access_manager" not in actor.risk_tags:
            findings.append(_finding(
                "admin_assigned_by_unusual_actor",
                "Admin Role Assigned By Unusual Actor",
                "High",
                change.target_user_id,
                change.timestamp,
                "Privileged role was assigned by an actor outside normal access-management workflow.",
                {"actor": change.actor_user_id, "target_object": change.target_object, "details": change.details},
                20,
            ))

    for user_id, target_changes in changes_by_target.items():
        sensitive_success = [
            event for event in events_by_user[user_id]
            if event.result == "success" and event.action in {"export_records", "download_bulk", "delete_user", "assign_role", "read_phi", "export_payroll"}
        ]
        for change in target_changes:
            if change.change_type not in {"role_granted", "group_added"}:
                continue
            change_time = parse_time(change.timestamp)
            after = [event for event in sensitive_success if timedelta(0) <= parse_time(event.timestamp) - change_time <= timedelta(hours=24)]
            if after:
                findings.append(_finding(
                    "role_change_sensitive_access",
                    "Role Change Followed By Sensitive Access",
                    "Critical",
                    user_id,
                    after[0].timestamp,
                    "Sensitive access occurred shortly after a role or group change.",
                    {"change": change.__dict__, "access_event": after[0].__dict__},
                    30,
                ))
                break

    for user_id, user_events in events_by_user.items():
        denied = [event for event in user_events if event.result in {"denied", "failure"}]
        success = [event for event in user_events if event.result == "success"]
        for event in success:
            recent_denied = [
                d for d in denied
                if d.action == event.action and timedelta(0) <= parse_time(event.timestamp) - parse_time(d.timestamp) <= timedelta(hours=12)
            ]
            if len(recent_denied) >= 2:
                findings.append(_finding(
                    "denied_then_success",
                    "Repeated Access Denied Followed By Success",
                    "High",
                    user_id,
                    event.timestamp,
                    "Multiple denied attempts were followed by successful access for the same action.",
                    {"denied_count": len(recent_denied), "success_event": event.__dict__},
                    20,
                ))
                break

    unique = {}
    for finding in findings:
        key = (finding.detection_id, finding.user_id, finding.timestamp, finding.reason)
        unique[key] = finding
    return sorted(unique.values(), key=lambda item: (item.timestamp, item.user_id, item.detection_id), reverse=True)
