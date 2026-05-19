from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


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

