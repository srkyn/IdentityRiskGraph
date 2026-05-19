from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.models import CloudTrailEvent, NormalizedEvent


def load_cloudtrail(path: str | Path) -> list[CloudTrailEvent]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict) and "Records" in payload:
        records = payload["Records"]
    elif isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        records = [payload]
    else:
        raise ValueError("CloudTrail payload must be a single event, a list, or a Records[] object.")
    return [parse_cloudtrail_record(record) for record in records]


def parse_cloudtrail_record(record: dict[str, Any]) -> CloudTrailEvent:
    identity = record.get("userIdentity", {}) or {}
    actor = _actor_from_identity(identity)
    return CloudTrailEvent(
        event_name=record.get("eventName", ""),
        event_time=record.get("eventTime", ""),
        actor=actor,
        actor_type=identity.get("type", "Unknown"),
        source_ip=record.get("sourceIPAddress", "unknown"),
        user_agent=record.get("userAgent", "unknown"),
        request_parameters=record.get("requestParameters", {}) or {},
        recipient_account_id=str(record.get("recipientAccountId", "")),
        aws_region=record.get("awsRegion", "unknown"),
        event_source=record.get("eventSource", "unknown"),
        raw=record,
    )


def normalize_cloudtrail_event(event: CloudTrailEvent) -> NormalizedEvent:
    severity = "Medium" if event.event_name in {"AttachUserPolicy", "PutUserPolicy", "AddUserToGroup"} else "Low"
    if event.event_name in {"DeleteTrail", "StopLogging"}:
        severity = "High"
    return NormalizedEvent(
        event_id=event.raw.get("eventID", f"cloudtrail-{event.event_time}-{event.event_name}"),
        actor=event.actor,
        identity=_target_from_request(event),
        device="aws-control-plane",
        activity_name=event.event_name,
        activity_id=event.event_name,
        category="Identity",
        class_name="AWS IAM Control Plane",
        severity=severity,
        src_endpoint=event.source_ip,
        cloud="AWS",
        resource=_target_from_request(event),
        status="success" if not event.raw.get("errorCode") else "failure",
        time=event.event_time,
        geo="CloudTrail",
        raw=event.raw,
    )


def normalize_cloudtrail_events(events: list[CloudTrailEvent]) -> list[NormalizedEvent]:
    return [normalize_cloudtrail_event(event) for event in events]


def _actor_from_identity(identity: dict[str, Any]) -> str:
    if identity.get("userName"):
        return identity["userName"]
    if identity.get("arn"):
        return identity["arn"].split("/")[-1]
    session_issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})
    if session_issuer.get("userName"):
        return session_issuer["userName"]
    return identity.get("principalId", "unknown")


def _target_from_request(event: CloudTrailEvent) -> str:
    params = event.request_parameters
    for key in ("userName", "groupName", "roleName", "policyName"):
        if params.get(key):
            return str(params[key])
    return event.actor

