from __future__ import annotations

from src.models import Event, NormalizedEvent, Resource


EVENT_MAP = {
    "login": ("Authentication", "auth", "Identity", "Authentication", "Informational"),
    "admin_action": ("Administrative Action", "iam_admin", "Identity", "IAM Activity", "Medium"),
    "resource_access": ("Resource Access", "data_access", "Data", "Data Activity", "Low"),
    "role_assignment": ("Role Assignment", "role_change", "Identity", "IAM Change", "Medium"),
    "group_membership": ("Group Membership Change", "group_change", "Identity", "IAM Change", "Medium"),
    "access_denied": ("Access Denied", "access_denied", "Data", "Access Activity", "Low"),
    "export": ("Data Export", "data_export", "Data", "Data Activity", "Medium"),
}


def normalize_events(events: list[Event], resources: list[Resource]) -> list[NormalizedEvent]:
    resource_cloud = {resource.resource_id: resource.cloud for resource in resources}
    normalized = []
    for event in events:
        activity_name, activity_id, category, class_name, severity = EVENT_MAP.get(
            event.event_type, ("Activity", event.event_type, "Other", "Generic Activity", "Low")
        )
        if event.result.lower() in {"failure", "denied"}:
            severity = "Medium"
        normalized.append(
            NormalizedEvent(
                event_id=event.event_id,
                actor=event.user_id,
                identity=event.user_id,
                device=event.device_id,
                activity_name=activity_name,
                activity_id=activity_id,
                category=category,
                class_name=class_name,
                severity=severity,
                src_endpoint=event.source_ip,
                cloud=resource_cloud.get(event.resource, "Hybrid"),
                resource=event.resource,
                status=event.result,
                time=event.timestamp,
                geo=event.geo,
                raw=event.__dict__,
            )
        )
    return normalized

