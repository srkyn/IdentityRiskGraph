from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import TypeVar

from src.config import DATA_DIR
from src.models import AccountChange, Device, Event, Group, Permission, Resource, Role, User

T = TypeVar("T")


def _load_json(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _coerce(model: type[T], payload: dict) -> T:
    names = {field.name for field in fields(model)}
    return model(**{key: value for key, value in payload.items() if key in names})


def load_collection(filename: str, model: type[T]) -> list[T]:
    return [_coerce(model, item) for item in _load_json(DATA_DIR / filename)]


def load_all_data(data_dir: Path = DATA_DIR) -> dict:
    global DATA_DIR
    original = DATA_DIR
    DATA_DIR = data_dir
    try:
        return {
            "users": load_collection("users.json", User),
            "groups": load_collection("groups.json", Group),
            "roles": load_collection("roles.json", Role),
            "permissions": load_collection("permissions.json", Permission),
            "role_bindings": _load_json(data_dir / "role_bindings.json"),
            "devices": load_collection("devices.json", Device),
            "events": load_collection("events.json", Event),
            "resources": load_collection("resources.json", Resource),
            "account_changes": load_collection("account_changes.json", AccountChange),
        }
    finally:
        DATA_DIR = original


def index_by(items: list, attr: str) -> dict:
    return {getattr(item, attr): item for item in items}

