from __future__ import annotations

from datetime import datetime, timezone
from math import asin, cos, radians, sin, sqrt


GEO_COORDS = {
    "Boston, US": (42.3601, -71.0589),
    "New York, US": (40.7128, -74.0060),
    "Chicago, US": (41.8781, -87.6298),
    "Seattle, US": (47.6062, -122.3321),
    "San Francisco, US": (37.7749, -122.4194),
    "Miami, US": (25.7617, -80.1918),
    "London, UK": (51.5072, -0.1276),
    "Dublin, IE": (53.3498, -6.2603),
    "Lagos, NG": (6.5244, 3.3792),
    "Singapore, SG": (1.3521, 103.8198),
    "Tokyo, JP": (35.6762, 139.6503),
}


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def days_between(a: str, b: str) -> int:
    return abs((parse_time(a) - parse_time(b)).days)


def risk_band(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def haversine_miles(start_geo: str, end_geo: str) -> float:
    if start_geo not in GEO_COORDS or end_geo not in GEO_COORDS:
        return 0.0
    lat1, lon1 = GEO_COORDS[start_geo]
    lat2, lon2 = GEO_COORDS[end_geo]
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return 3958.8 * 2 * asin(sqrt(a))


def velocity_mph(start_time: str, start_geo: str, end_time: str, end_geo: str) -> float:
    hours = abs((parse_time(end_time) - parse_time(start_time)).total_seconds()) / 3600
    if hours == 0:
        return 0.0
    return haversine_miles(start_geo, end_geo) / hours


def clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))

