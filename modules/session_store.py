"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

import json
from datetime import datetime
from typing import Any
from modules.paths import get_project_root
PROJECT_ROOT = get_project_root()
DATA_DIR = PROJECT_ROOT / 'data'
STORE_FILE = DATA_DIR / 'last_results.json'

def _load_all() -> dict[str, Any]:
    if not STORE_FILE.exists():
        return {}
    try:
        with STORE_FILE.open('r', encoding='utf-8') as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError):
        return {}

def save(module_key: str, data: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    stored = _load_all()
    stored[module_key] = {'timestamp': datetime.now().isoformat(timespec='seconds'), 'data': data}
    with STORE_FILE.open('w', encoding='utf-8') as handle:
        json.dump(stored, handle, indent=2, ensure_ascii=False)

def get(module_key: str) -> dict[str, Any] | None:
    entry = _load_all().get(module_key)
    if not entry:
        return None
    return entry

def get_keys(keys: list[str]) -> dict[str, Any]:
    stored = _load_all()
    return {key: stored[key] for key in keys if key in stored}
