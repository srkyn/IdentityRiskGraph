from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from src.models import AWSIAMFinding, DetectionFinding


def findings_to_splunk_json(findings: list[DetectionFinding | AWSIAMFinding], index: str = "identityriskgraph") -> str:
    events = [to_splunk_event(finding, index=index) for finding in findings]
    return json.dumps(events, indent=2, default=str)


def to_splunk_event(finding: DetectionFinding | AWSIAMFinding, index: str = "identityriskgraph") -> dict[str, Any]:
    payload = asdict(finding)
    is_cloudtrail = isinstance(finding, AWSIAMFinding)
    return {
        "time": payload.get("timestamp"),
        "source": "identityriskgraph:cloudtrail" if is_cloudtrail else "identityriskgraph:dashboard",
        "sourcetype": "aws:cloudtrail:iam:detection" if is_cloudtrail else "identityriskgraph:finding",
        "index": index,
        "detection_name": payload.get("detection_name"),
        "severity": payload.get("severity"),
        "user": payload.get("target_identity") or payload.get("user_id"),
        "actor": payload.get("actor") or payload.get("evidence", {}).get("actor") or payload.get("user_id"),
        "src_ip": payload.get("source_ip") or payload.get("evidence", {}).get("source_ip"),
        "event_name": payload.get("event_name") or payload.get("evidence", {}).get("event_name"),
        "risk_score_delta": payload.get("risk_score_delta"),
        "mitre_technique": payload.get("mitre_technique"),
        "recommended_action": payload.get("recommended_action"),
    }
