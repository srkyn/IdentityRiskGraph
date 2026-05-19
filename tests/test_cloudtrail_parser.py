from pathlib import Path

from src.cloudtrail_parser import load_cloudtrail, normalize_cloudtrail_events


SAMPLE = Path("data/cloudtrail/sample_cloudtrail_iam_events.json")


def test_records_array_parsing():
    events = load_cloudtrail(SAMPLE)
    assert len(events) >= 17
    assert events[0].event_name == "GetCallerIdentity"
    assert events[0].actor == "priya.shah@hospital.example"


def test_normalized_output_format():
    events = load_cloudtrail(SAMPLE)
    normalized = normalize_cloudtrail_events(events)
    first = normalized[0]
    assert first.actor
    assert first.identity
    assert first.cloud == "AWS"
    assert first.class_name == "AWS IAM Control Plane"
    assert first.time.endswith("Z")

