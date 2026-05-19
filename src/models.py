from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class User:
    user_id: str
    display_name: str
    email: str
    department: str
    job_title: str
    user_type: str
    manager: str | None
    status: str
    created_at: str
    last_login: str
    normal_locations: list[str]
    assigned_groups: list[str]
    direct_roles: list[str]
    risk_tags: list[str]


@dataclass(frozen=True)
class Group:
    group_id: str
    name: str
    description: str
    members: list[str]
    nested_groups: list[str]
    assigned_roles: list[str]
    is_privileged: bool
    is_role_assignable: bool
    owner: str


@dataclass(frozen=True)
class Role:
    role_id: str
    name: str
    cloud: str
    privilege_level: int
    permissions: list[str]
    sensitive_actions: list[str]
    description: str
    deny_permissions: list[str] = field(default_factory=list)
    permissions_boundary: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Permission:
    permission_id: str
    name: str
    category: str
    sensitivity: str
    description: str


@dataclass(frozen=True)
class Device:
    device_id: str
    hostname: str
    owner_user_id: str
    platform: str
    managed: bool
    compliant: bool
    trust_level: str
    last_seen: str


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: str
    event_type: str
    user_id: str
    device_id: str
    source_ip: str
    geo: str
    resource: str
    action: str
    result: str
    raw_message: str


@dataclass(frozen=True)
class Resource:
    resource_id: str
    name: str
    type: str
    cloud: str
    sensitivity: str
    owner_department: str


@dataclass(frozen=True)
class AccountChange:
    change_id: str
    timestamp: str
    actor_user_id: str
    target_user_id: str
    change_type: str
    target_object: str
    details: dict[str, Any]


@dataclass(frozen=True)
class NormalizedEvent:
    event_id: str
    actor: str
    identity: str
    device: str
    activity_name: str
    activity_id: str
    category: str
    class_name: str
    severity: str
    src_endpoint: str
    cloud: str
    resource: str
    status: str
    time: str
    geo: str
    raw: dict[str, Any]


@dataclass
class PrivilegePath:
    user_id: str
    role_id: str
    permission: str
    path: list[str]
    inherited: bool
    nested_depth: int


@dataclass
class EffectiveAccess:
    user_id: str
    direct_roles: set[str]
    inherited_roles: set[str]
    permissions: set[str]
    denied_permissions: set[str]
    boundary_limited_permissions: set[str]
    sensitive_permissions: set[str]
    paths: list[PrivilegePath]
    max_privilege_level: int
    nested_group_depth: int


@dataclass
class DetectionFinding:
    detection_id: str
    detection_name: str
    severity: str
    user_id: str
    entity_type: str
    timestamp: str
    reason: str
    evidence: dict[str, Any]
    risk_score_delta: int
    mitre_technique: str
    recommended_action: str
    investigation_questions: list[str]


@dataclass(frozen=True)
class CloudTrailEvent:
    event_name: str
    event_time: str
    actor: str
    actor_type: str
    source_ip: str
    user_agent: str
    request_parameters: dict[str, Any]
    recipient_account_id: str
    aws_region: str
    event_source: str
    raw: dict[str, Any]


@dataclass(frozen=True)
class AWSIAMFinding:
    detection_id: str
    detection_name: str
    severity: str
    event_name: str
    actor: str
    target_identity: str
    source_ip: str
    timestamp: str
    reason: str
    evidence: dict[str, Any]
    recommended_action: str
    mitre_technique: str
    risk_score_delta: int


@dataclass
class RiskFactor:
    factor: str
    points: int
    reason: str
    evidence: str


@dataclass
class RiskProfile:
    user_id: str
    score: int
    band: str
    top_reason: str
    factors: list[RiskFactor]
