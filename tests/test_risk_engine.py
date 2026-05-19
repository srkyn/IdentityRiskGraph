from src.detections import run_detections
from src.ingest import load_all_data
from src.permission_resolver import resolve_all_access
from src.risk_engine import score_all_users


def test_risk_score_bands_and_explainability_output():
    data = load_all_data()
    access = resolve_all_access(data["users"], data["groups"], data["roles"])
    findings = run_detections(data["users"], data["events"], data["devices"], data["resources"], data["account_changes"], access)
    risks = score_all_users(data["users"], access, findings, data["events"], data["devices"])

    assert risks["u008"].band == "Critical"
    assert 0 <= risks["u008"].score <= 100
    assert risks["u008"].factors
    assert all(factor.factor and factor.reason and factor.evidence for factor in risks["u008"].factors)

