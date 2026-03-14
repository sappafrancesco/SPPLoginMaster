"""
SPPLoginMaster - App Discovery
Finds installed apps (snap, flatpak, .deb) and their data directories
"""

import subprocess
import os
from pathlib import Path


def find_snap_apps() -> list[dict]:
    """Return list of installed snap apps."""
    apps = []
    try:
        result = subprocess.run(
            ["snap", "list"], capture_output=True, text=True
        )
        lines = result.stdout.strip().splitlines()[1:]  # skip header
        for line in lines:
            parts = line.split()
            if len(parts) >= 1:
                name = parts[0]
                snap_data = Path.home() / "snap" / name / "common"
                desktop = _find_desktop_file(name)
                apps.append({
                    "id": f"snap:{name}",
                    "name": name,
                    "type": "snap",
                    "data_path": str(snap_data),
                    "launch_cmd": f"snap run {name}",
                    "desktop_file": desktop,
                    "icon": _get_snap_icon(name),
                })
    except Exception:
        pass
    return apps


def find_flatpak_apps() -> list[dict]:
    """Return list of installed flatpak apps."""
    apps = []
    try:
        result = subprocess.run(
            ["flatpak", "list", "--app", "--columns=application,name"],
            capture_output=True, text=True
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                app_id, name = parts[0], parts[1]
                data_path = Path.home() / ".var" / "app" / app_id
                desktop = _find_desktop_file_flatpak(app_id)
                apps.append({
                    "id": f"flatpak:{app_id}",
                    "name": name,
                    "type": "flatpak",
                    "data_path": str(data_path),
                    "launch_cmd": f"flatpak run {app_id}",
                    "desktop_file": desktop,
                    "icon": None,
                })
    except Exception:
        pass
    return apps


def find_deb_apps() -> list[dict]:
    """Return list of common .deb apps with known data dirs."""
    apps = []
    known_apps = [
        {
            "name": "Firefox",
            "binary": "firefox",
            "data_path": str(Path.home() / ".mozilla" / "firefox"),
            "desktop": "/usr/share/applications/firefox.desktop",
        },
        {
            "name": "Thunderbird",
            "binary": "thunderbird",
            "data_path": str(Path.home() / ".thunderbird"),
            "desktop": "/usr/share/applications/thunderbird.desktop",
        },
        {
            "name": "Chrome",
            "binary": "google-chrome",
            "data_path": str(Path.home() / ".config" / "google-chrome"),
            "desktop": "/usr/share/applications/google-chrome.desktop",
        },
        {
            "name": "Chromium",
            "binary": "chromium-browser",
            "data_path": str(Path.home() / ".config" / "chromium"),
            "desktop": "/usr/share/applications/chromium-browser.desktop",
        },
        {
            "name": "Signal",
            "binary": "signal-desktop",
            "data_path": str(Path.home() / ".config" / "Signal"),
            "desktop": "/usr/share/applications/signal-desktop.desktop",
        },
        {
            "name": "Telegram",
            "binary": "telegram-desktop",
            "data_path": str(Path.home() / ".local" / "share" / "TelegramDesktop"),
            "desktop": "/usr/share/applications/telegram-desktop.desktop",
        },
        {
            "name": "VSCode",
            "binary": "code",
            "data_path": str(Path.home() / ".config" / "Code"),
            "desktop": "/usr/share/applications/code.desktop",
        },
    ]

    for app in known_apps:
        binary = app.pop("binary")
        if _is_binary_installed(binary):
            apps.append({
                "id": f"deb:{binary}",
                "type": "deb",
                "launch_cmd": binary,
                "desktop_file": app["desktop"] if Path(app["desktop"]).exists() else None,
                "icon": None,
                **app,
            })
    return apps


def get_all_apps() -> list[dict]:
    """Return all installed apps across all package managers."""
    apps = []
    apps.extend(find_snap_apps())
    apps.extend(find_flatpak_apps())
    apps.extend(find_deb_apps())
    return apps


def _is_binary_installed(binary: str) -> bool:
    import shutil
    return shutil.which(binary) is not None


def _find_desktop_file(snap_name: str) -> str | None:
    """Find .desktop file for a snap app."""
    paths = [
        Path("/var/lib/snapd/desktop/applications"),
        Path.home() / ".local" / "share" / "applications",
    ]
    for base in paths:
        for f in base.glob(f"{snap_name}*.desktop"):
            return str(f)
    return None


def _find_desktop_file_flatpak(app_id: str) -> str | None:
    paths = [
        Path("/var/lib/flatpak/exports/share/applications"),
        Path.home() / ".local" / "share" / "flatpak" / "exports" / "share" / "applications",
    ]
    for base in paths:
        candidate = base / f"{app_id}.desktop"
        if candidate.exists():
            return str(candidate)
    return None


def _get_snap_icon(snap_name: str) -> str | None:
    icon_path = Path(f"/snap/{snap_name}/current/meta/gui/icon.png")
    if icon_path.exists():
        return str(icon_path)
    return None
