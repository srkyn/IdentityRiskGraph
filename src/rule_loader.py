from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from src.models import AWSIAMFinding, CloudTrailEvent


@dataclass(frozen=True)
class YAMLDetectionRule:
    id: str
    name: str
    eventName: str
    severity: str
    match_fields: dict[str, Any]
    reason_template: str
    recommended_action: str
    mitre_technique: str
    risk_score_delta: int


def load_yaml_rules(path: str | Path) -> list[YAMLDetectionRule]:
    rule_path = Path(path)
    if not rule_path.exists():
        raise FileNotFoundError(f"Detection rule file not found: {rule_path}")
    payload = yaml.safe_load(rule_path.read_text(encoding="utf-8")) or {}
    rules = payload.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("Detection rule YAML must contain a top-level rules list.")
    return [_coerce_rule(rule) for rule in rules]


def evaluate_yaml_rules(events: list[CloudTrailEvent], rules: list[YAMLDetectionRule]) -> list[AWSIAMFinding]:
    findings: list[AWSIAMFinding] = []
    for event in events:
        for rule in rules:
            if event.event_name != rule.eventName:
                continue
            if not _matches_fields(event.raw, rule.match_fields):
                continue
            target = _target_identity(event)
            context = {
                "actor": event.actor,
                "target_identity": target,
                "groupName": event.request_parameters.get("groupName", ""),
                "trailName": event.request_parameters.get("name", "trail"),
                "policyArn": event.request_parameters.get("policyArn", ""),
            }
            findings.append(
                AWSIAMFinding(
                    detection_id=rule.id,
                    detection_name=rule.name,
                    severity=rule.severity,
                    event_name=event.event_name,
                    actor=event.actor,
                    target_identity=target,
                    source_ip=event.source_ip,
                    timestamp=event.event_time,
                    reason=rule.reason_template.format(**context),
                    evidence={
                        "rule_id": rule.id,
                        "match_fields": rule.match_fields,
                        "requestParameters": event.request_parameters,
                    },
                    recommended_action=rule.recommended_action,
                    mitre_technique=rule.mitre_technique,
                    risk_score_delta=rule.risk_score_delta,
                )
            )
    return sorted(findings, key=lambda finding: (finding.timestamp, finding.severity), reverse=True)


def _coerce_rule(rule: dict[str, Any]) -> YAMLDetectionRule:
    required = {
        "id",
        "name",
        "eventName",
        "severity",
        "match_fields",
        "reason_template",
        "recommended_action",
        "mitre_technique",
        "risk_score_delta",
    }
    missing = sorted(required - set(rule))
    if missing:
        raise ValueError(f"Detection rule {rule.get('id', '<unknown>')} is missing fields: {', '.join(missing)}")
    return YAMLDetectionRule(
        id=str(rule["id"]),
        name=str(rule["name"]),
        eventName=str(rule["eventName"]),
        severity=str(rule["severity"]),
        match_fields=dict(rule["match_fields"] or {}),
        reason_template=str(rule["reason_template"]),
        recommended_action=str(rule["recommended_action"]),
        mitre_technique=str(rule["mitre_technique"]),
        risk_score_delta=int(rule["risk_score_delta"]),
    )


def _matches_fields(record: dict[str, Any], match_fields: dict[str, Any]) -> bool:
    for path, expected in match_fields.items():
        actual = _get_path(record, path)
        if isinstance(expected, list):
            if str(actual).lower() not in {str(item).lower() for item in expected}:
                return False
        elif expected is not None and str(expected).lower() not in str(actual).lower():
            return False
    return True


def _get_path(record: dict[str, Any], path: str) -> Any:
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, dict):
            return ""
        current = current.get(part, "")
    return current


def _target_identity(event: CloudTrailEvent) -> str:
    for key in ("userName", "groupName", "roleName", "policyArn", "name"):
        if event.request_parameters.get(key):
            return str(event.request_parameters[key])
    return event.actor
