from __future__ import annotations

import json
from collections import defaultdict

from src.models import AWSIAMFinding, CloudTrailEvent, DetectionFinding, User


MITRE_CLOUD_IAM = {
    "admin_policy_attached_user": "T1098 Account Manipulation",
    "admin_policy_attached_group": "T1098.003 Additional Cloud Roles",
    "user_added_privileged_group": "T1098.003 Additional Cloud Roles",
    "inline_user_policy_created": "T1098 Account Manipulation",
    "inline_group_policy_created": "T1098 Account Manipulation",
    "access_key_created_non_service_user": "T1098.001 Additional Cloud Credentials",
    "console_login_unusual_ip": "T1078.004 Cloud Accounts",
    "cloudtrail_logging_stopped": "T1562.008 Disable Cloud Logs",
    "trail_deleted": "T1562.008 Disable Cloud Logs",
    "assume_sensitive_role": "T1078.004 Cloud Accounts",
    "policy_version_broadened": "T1098 Account Manipulation",
    "login_profile_dormant_or_service": "T1098 Account Manipulation",
    "iam_recon_before_privilege_change": "T1087 Account Discovery / T1069.003 Cloud Groups",
    "assume_role_policy_opened": "T1098 Account Manipulation",
}

PRIVILEGED_GROUPS = {"admins", "administrators", "security-admins", "iam-admins", "break-glass-admins"}
SENSITIVE_ROLES = {"OrganizationAccountAccessRole", "SecurityAuditAdmin", "AdminRole", "BreakGlassRole", "ProductionAdmin"}
UNUSUAL_IP_PREFIXES = ("203.0.113.", "198.51.100.", "45.155.", "185.220.")
RECON_EVENTS = {"GetCallerIdentity", "ListAttachedUserPolicies", "ListGroupsForUser"}


def detect_aws_iam_risks(events: list[CloudTrailEvent]) -> list[AWSIAMFinding]:
    findings: list[AWSIAMFinding] = []
    sorted_events = sorted(events, key=lambda event: event.event_time)

    for event in sorted_events:
        params = event.request_parameters
        policy_arn = str(params.get("policyArn", ""))
        target_user = str(params.get("userName", ""))
        target_group = str(params.get("groupName", ""))

        if event.event_name == "AttachUserPolicy" and policy_arn.endswith("AdministratorAccess"):
            findings.append(_finding(
                "admin_policy_attached_user",
                "AdministratorAccess Attached To User",
                "High",
                event,
                target_user,
                f"{target_user} was granted AdministratorAccess directly.",
                {"policyArn": policy_arn, "requestParameters": params},
                "Review policy attachment, validate change ticket, and confirm business justification.",
                24,
            ))
        elif event.event_name == "AttachGroupPolicy" and policy_arn.endswith("AdministratorAccess"):
            findings.append(_finding(
                "admin_policy_attached_group",
                "AdministratorAccess Attached To Group",
                "Critical",
                event,
                target_group,
                f"{target_group} was granted AdministratorAccess, affecting all current and future members.",
                {"policyArn": policy_arn, "requestParameters": params},
                "Review group membership, remove broad policy if not approved, and validate group owner.",
                30,
            ))
        elif event.event_name == "AddUserToGroup" and target_group.lower() in PRIVILEGED_GROUPS:
            findings.append(_finding(
                "user_added_privileged_group",
                "User Added To Privileged Group",
                "High",
                event,
                target_user,
                f"{target_user} was added to privileged group {target_group}.",
                {"groupName": target_group, "userName": target_user},
                "Validate approval, review group privileges, and confirm the actor normally manages access.",
                22,
            ))
        elif event.event_name == "PutUserPolicy":
            findings.append(_finding(
                "inline_user_policy_created",
                "Inline Policy Created For User",
                "High",
                event,
                target_user,
                "Inline IAM policy was created directly on a user, which can bypass normal managed-policy review.",
                {"policyName": params.get("policyName"), "policyDocument": params.get("policyDocument")},
                "Inspect policy document, compare to approved role model, and remove direct inline grants if unnecessary.",
                20,
            ))
        elif event.event_name == "PutGroupPolicy":
            findings.append(_finding(
                "inline_group_policy_created",
                "Inline Policy Created For Group",
                "High",
                event,
                target_group,
                "Inline IAM policy was created on a group and may affect multiple identities.",
                {"policyName": params.get("policyName"), "policyDocument": params.get("policyDocument")},
                "Review group membership and policy scope, then replace with reviewed managed policy where possible.",
                20,
            ))
        elif event.event_name == "CreateAccessKey" and not _service_style(target_user):
            findings.append(_finding(
                "access_key_created_non_service_user",
                "Access Key Created For Non-Service User",
                "Medium",
                event,
                target_user,
                "Long-lived access key was created for a human-style IAM user.",
                {"userName": target_user, "accessKeyId": params.get("accessKeyId", "redacted")},
                "Confirm key owner, rotate if unauthorized, and prefer role-based temporary credentials.",
                14,
            ))
        elif event.event_name == "ConsoleLogin" and _is_unusual_ip(event.source_ip):
            findings.append(_finding(
                "console_login_unusual_ip",
                "Console Login From Unusual IP",
                "Medium",
                event,
                event.actor,
                "AWS console login came from an IP range marked unusual in the sample baseline.",
                {"sourceIPAddress": event.source_ip, "userAgent": event.user_agent},
                "Validate MFA, geolocation, device posture, and whether the IP is expected for this actor.",
                12,
            ))
        elif event.event_name == "StopLogging":
            findings.append(_finding(
                "cloudtrail_logging_stopped",
                "CloudTrail Logging Stopped",
                "Critical",
                event,
                str(params.get("name", "trail")),
                "CloudTrail logging was stopped, reducing visibility into control-plane activity.",
                {"trailName": params.get("name"), "sourceIPAddress": event.source_ip},
                "Re-enable logging, preserve available logs, and investigate actor activity before and after the event.",
                34,
            ))
        elif event.event_name == "DeleteTrail":
            findings.append(_finding(
                "trail_deleted",
                "CloudTrail Trail Deleted",
                "Critical",
                event,
                str(params.get("name", "trail")),
                "CloudTrail trail was deleted, which is a high-confidence defense-evasion signal.",
                {"trailName": params.get("name"), "sourceIPAddress": event.source_ip},
                "Restore logging, check organization trails, and escalate as potential defense evasion.",
                36,
            ))
        elif event.event_name == "AssumeRole" and str(params.get("roleArn", "")).split("/")[-1] in SENSITIVE_ROLES:
            findings.append(_finding(
                "assume_sensitive_role",
                "AssumeRole Into Sensitive Role",
                "High",
                event,
                str(params.get("roleArn", "")),
                "Actor assumed a sensitive administrative role.",
                {"roleArn": params.get("roleArn"), "roleSessionName": params.get("roleSessionName")},
                "Validate the source principal, session purpose, MFA, and whether this role assumption was expected.",
                22,
            ))
        elif event.event_name in {"CreatePolicyVersion", "SetDefaultPolicyVersion"} and _policy_broadened(params):
            findings.append(_finding(
                "policy_version_broadened",
                "Policy Version Changed To Broaden Access",
                "High",
                event,
                str(params.get("policyArn", params.get("policyName", "policy"))),
                "Policy version update appears to broaden access with wildcard actions or resources.",
                {"policyArn": params.get("policyArn"), "policyDocument": params.get("policyDocument"), "setAsDefault": params.get("setAsDefault")},
                "Compare policy diff, validate approver, and roll back if the broader default version was not approved.",
                22,
            ))
        elif event.event_name == "UpdateAssumeRolePolicy" and _trust_policy_opened(params):
            findings.append(_finding(
                "assume_role_policy_opened",
                "Assume Role Trust Policy Opened Broadly",
                "High",
                event,
                str(params.get("roleName", "role")),
                "AssumeRole trust policy appears to allow a broad or wildcard principal.",
                {"roleName": params.get("roleName"), "policyDocument": params.get("policyDocument")},
                "Review the trust policy, confirm intended principals, and roll back wildcard trust if not approved.",
                22,
            ))
        elif event.event_name == "CreateLoginProfile" and (_service_style(target_user) or _dormant_style(target_user)):
            findings.append(_finding(
                "login_profile_dormant_or_service",
                "Login Profile Created For Dormant Or Service-Style Account",
                "High",
                event,
                target_user,
                "Console password profile was created for an account that should not normally use console login.",
                {"userName": target_user, "passwordResetRequired": params.get("passwordResetRequired")},
                "Disable the login profile unless approved and check for follow-on console activity.",
                20,
            ))

    findings.extend(_detect_recon_before_privilege_change(sorted_events))
    return sorted(findings, key=lambda finding: (finding.timestamp, finding.severity), reverse=True)


def cloudtrail_findings_to_detection_findings(findings: list[AWSIAMFinding], users: list[User]) -> list[DetectionFinding]:
    users_by_email = {user.email.lower(): user for user in users}
    converted = []
    for finding in findings:
        user = users_by_email.get(finding.target_identity.lower()) or users_by_email.get(finding.actor.lower())
        if not user:
            continue
        converted.append(DetectionFinding(
            detection_id=f"aws_{finding.detection_id}",
            detection_name=f"AWS IAM: {finding.detection_name}",
            severity=finding.severity,
            user_id=user.user_id,
            entity_type="aws_iam_identity",
            timestamp=finding.timestamp,
            reason=finding.reason,
            evidence=finding.evidence | {"actor": finding.actor, "source_ip": finding.source_ip, "event_name": finding.event_name},
            risk_score_delta=finding.risk_score_delta,
            mitre_technique=finding.mitre_technique,
            recommended_action=finding.recommended_action,
            investigation_questions=[
                "Was this IAM control-plane change approved?",
                "Does the actor normally administer this target identity or policy?",
                "Did reconnaissance or suspicious login activity occur before the change?",
            ],
        ))
    return converted


def _finding(
    detection_id: str,
    detection_name: str,
    severity: str,
    event: CloudTrailEvent,
    target_identity: str,
    reason: str,
    evidence: dict,
    recommended_action: str,
    risk_score_delta: int,
) -> AWSIAMFinding:
    return AWSIAMFinding(
        detection_id=detection_id,
        detection_name=detection_name,
        severity=severity,
        event_name=event.event_name,
        actor=event.actor,
        target_identity=target_identity or event.actor,
        source_ip=event.source_ip,
        timestamp=event.event_time,
        reason=reason,
        evidence=evidence,
        recommended_action=recommended_action,
        mitre_technique=MITRE_CLOUD_IAM[detection_id],
        risk_score_delta=risk_score_delta,
    )


def _service_style(user_name: str) -> bool:
    value = user_name.lower()
    return value.startswith(("svc-", "service-", "app-")) or "service" in value


def _dormant_style(user_name: str) -> bool:
    return "dormant" in user_name.lower() or "legacy" in user_name.lower()


def _is_unusual_ip(source_ip: str) -> bool:
    return source_ip.startswith(UNUSUAL_IP_PREFIXES)


def _policy_broadened(params: dict) -> bool:
    document = _policy_document(params)
    text = json.dumps(document) if isinstance(document, dict) else str(document)
    return '"Action": "*"' in text or '"Action":"*"' in text or '"Resource": "*"' in text or '"Resource":"*"' in text


def _trust_policy_opened(params: dict) -> bool:
    document = _policy_document(params)
    text = json.dumps(document) if isinstance(document, dict) else str(document)
    return '"AWS": "*"' in text or '"AWS":"*"' in text or '"Principal": "*"' in text or '"Principal":"*"' in text


def _policy_document(params: dict):
    document = params.get("policyDocument", "")
    if isinstance(document, str):
        try:
            return json.loads(document)
        except json.JSONDecodeError:
            return document
    return document


def _detect_recon_before_privilege_change(events: list[CloudTrailEvent]) -> list[AWSIAMFinding]:
    by_actor: dict[str, list[CloudTrailEvent]] = defaultdict(list)
    findings = []
    privilege_events = {"AttachUserPolicy", "AttachGroupPolicy", "PutUserPolicy", "PutGroupPolicy", "AddUserToGroup"}
    for event in events:
        by_actor[event.actor].append(event)
    for actor_events in by_actor.values():
        for idx, event in enumerate(actor_events):
            if event.event_name not in privilege_events:
                continue
            prior = [candidate for candidate in actor_events[max(0, idx - 6):idx] if candidate.event_name in RECON_EVENTS]
            if len(prior) >= 2:
                findings.append(_finding(
                    "iam_recon_before_privilege_change",
                    "Repeated IAM Reconnaissance Before Privilege Change",
                    "Medium",
                    event,
                    str(event.request_parameters.get("userName", event.request_parameters.get("groupName", event.actor))),
                    "Actor performed multiple IAM discovery actions shortly before a privilege change.",
                    {"recon_events": [p.event_name for p in prior], "privilege_event": event.event_name},
                    "Review the actor's full session, validate change intent, and look for unauthorized privilege escalation.",
                    14,
                ))
                break
    return findings
