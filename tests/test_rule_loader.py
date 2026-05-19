from src.rule_loader import load_yaml_rules


def test_load_cloudtrail_yaml_rules():
    rules = load_yaml_rules("rules/cloudtrail_iam_rules.yaml")
    ids = {rule.id for rule in rules}
    assert "admin_policy_attached_user" in ids
    assert "cloudtrail_logging_stopped" in ids
    assert all(rule.name and rule.eventName and rule.recommended_action for rule in rules)
