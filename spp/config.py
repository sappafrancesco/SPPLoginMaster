"""
SPPLoginMaster - Configuration Manager
Handles per-app config stored in ~/.config/spploginmaster/
"""

import base64
import json
import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "spploginmaster"
CONFIG_FILE = CONFIG_DIR / "apps.json"
GPG_KEY_FILE = Path.home() / ".config" / "spploginmaster" / "gpg_key_id"


def ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    ensure_config_dir()
    if not CONFIG_FILE.exists():
        return {}
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


def save_config(config: dict):
    ensure_config_dir()
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def get_app_config(app_id: str) -> dict | None:
    config = load_config()
    return config.get(app_id)


def set_app_config(app_id: str, app_data: dict):
    config = load_config()
    config[app_id] = app_data
    save_config(config)


def remove_app_config(app_id: str):
    config = load_config()
    if app_id in config:
        del config[app_id]
        save_config(config)


def list_apps() -> list[dict]:
    config = load_config()
    return [{"id": k, **v} for k, v in config.items()]


def get_gpg_key_id() -> str | None:
    if GPG_KEY_FILE.exists():
        return GPG_KEY_FILE.read_text().strip()
    return None


def set_gpg_key_id(key_id: str):
    ensure_config_dir()
    GPG_KEY_FILE.write_text(key_id)


def set_app_salt(app_id: str, salt: bytes):
    """Store the per-app PBKDF2 salt (base64-encoded) inside the app config."""
    config = load_config()
    if app_id in config:
        config[app_id]["auth_salt"] = base64.b64encode(salt).decode()
        save_config(config)


def get_app_salt(app_id: str) -> bytes | None:
    """Return the per-app PBKDF2 salt, or None if not present."""
    config = load_config()
    b64 = config.get(app_id, {}).get("auth_salt")
    return base64.b64decode(b64) if b64 else None
