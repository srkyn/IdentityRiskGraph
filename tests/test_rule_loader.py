from src.cloudtrail_parser import load_cloudtrail
from src.rule_loader import evaluate_yaml_rules, load_yaml_rules


def test_load_cloudtrail_yaml_rules():
    rules = load_yaml_rules("rules/cloudtrail_iam_rules.yaml")
    ids = {rule.id for rule in rules}
    assert "admin_policy_attached_user" in ids
    assert "cloudtrail_logging_stopped" in ids
    assert all(rule.name and rule.eventName and rule.recommended_action for rule in rules)


def test_evaluate_yaml_rules_against_cloudtrail_events():
    events = load_cloudtrail("data/cloudtrail/suspicious_cloudtrail_events.json")
    rules = load_yaml_rules("rules/cloudtrail_iam_rules.yaml")
    findings = evaluate_yaml_rules(events, rules)
    ids = {finding.detection_id for finding in findings}
    assert "admin_policy_attached_user" in ids
    assert "cloudtrail_logging_stopped" in ids
    assert all(finding.reason and finding.recommended_action for finding in findings)
