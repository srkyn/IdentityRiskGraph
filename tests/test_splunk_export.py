import json

from src.aws_iam_detections import detect_aws_iam_risks
from src.cloudtrail_parser import load_cloudtrail
from src.splunk_export import findings_to_splunk_json


def test_splunk_export_shape():
    findings = detect_aws_iam_risks(load_cloudtrail("data/cloudtrail/suspicious_cloudtrail_events.json"))
    events = json.loads(findings_to_splunk_json(findings))
    assert events
    assert {"time", "source", "sourcetype", "index", "detection_name", "severity", "user", "actor", "src_ip"}.issubset(events[0])
