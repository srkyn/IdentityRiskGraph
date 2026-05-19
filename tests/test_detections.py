from src.detections import run_detections
from src.ingest import load_all_data
from src.permission_resolver import resolve_all_access


def _findings():
    data = load_all_data()
    access = resolve_all_access(data["users"], data["groups"], data["roles"])
    return run_detections(data["users"], data["events"], data["devices"], data["resources"], data["account_changes"], access)


def test_toxic_permission_combination_detection():
    findings = _findings()
    assert any(f.detection_id == "toxic_permission_combination" for f in findings)


def test_stale_account_access_detection():
    findings = _findings()
    assert any(f.detection_id == "dormant_account_access" and f.user_id in {"u009", "u011"} for f in findings)


def test_impossible_travel_detection():
    findings = _findings()
    assert any(f.detection_id == "impossible_travel" and f.user_id == "u018" for f in findings)


def test_service_account_interactive_login_detection():
    findings = _findings()
    assert any(f.detection_id == "service_account_interactive_login" and f.user_id == "u012" for f in findings)

