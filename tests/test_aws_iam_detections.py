from pathlib import Path

from src.aws_iam_detections import detect_aws_iam_risks
from src.cloudtrail_parser import load_cloudtrail


SAMPLE = Path("data/cloudtrail/sample_cloudtrail_iam_events.json")


def _findings():
    return detect_aws_iam_risks(load_cloudtrail(SAMPLE))


def test_attach_user_policy_detection():
    findings = _findings()
    finding = next(f for f in findings if f.detection_id == "admin_policy_attached_user")
    assert finding.event_name == "AttachUserPolicy"
    assert finding.severity == "High"
    assert finding.target_identity == "john.contractor@example.com"


def test_add_user_to_group_detection():
    findings = _findings()
    finding = next(f for f in findings if f.detection_id == "user_added_privileged_group")
    assert finding.event_name == "AddUserToGroup"
    assert finding.severity == "High"


def test_stop_logging_detection():
    findings = _findings()
    finding = next(f for f in findings if f.detection_id == "cloudtrail_logging_stopped")
    assert finding.event_name == "StopLogging"
    assert finding.severity == "Critical"


def test_create_access_key_detection():
    findings = _findings()
    finding = next(f for f in findings if f.detection_id == "access_key_created_non_service_user")
    assert finding.event_name == "CreateAccessKey"
    assert finding.target_identity == "morgan.lee@hospital.example"
    assert finding.severity == "Medium"


def test_cloudtrail_finding_shape():
    finding = _findings()[0]
    assert finding.detection_id
    assert finding.detection_name
    assert finding.event_name
    assert finding.actor
    assert finding.source_ip
    assert finding.recommended_action
    assert finding.mitre_technique
    assert finding.risk_score_delta > 0

