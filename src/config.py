from __future__ import annotations

from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"

RISK_BANDS = {
    "Low": range(0, 30),
    "Medium": range(30, 60),
    "High": range(60, 80),
    "Critical": range(80, 101),
}

SEVERITY_POINTS = {
    "Low": 6,
    "Medium": 12,
    "High": 20,
    "Critical": 30,
}

SENSITIVE_ACTION_KEYWORDS = (
    "delete",
    "export",
    "download",
    "assign",
    "write",
    "disable",
    "secrets",
    "payroll",
    "phi",
    "admin",
)

