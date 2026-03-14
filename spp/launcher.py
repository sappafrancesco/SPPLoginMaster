"""
SPPLoginMaster - Desktop Launcher Manager
Creates and manages .desktop wrapper files for protected apps
"""

import shutil
import subprocess
from pathlib import Path

DESKTOP_DIR = Path.home() / ".local" / "share" / "applications"
SPP_WRAPPER_DIR = Path.home() / ".local" / "bin" / "spp-wrappers"


def ensure_dirs():
    DESKTOP_DIR.mkdir(parents=True, exist_ok=True)
    SPP_WRAPPER_DIR.mkdir(parents=True, exist_ok=True)


def create_wrapper_script(app_config: dict) -> Path:
    """
    Create a bash wrapper script for a protected app.

    Authentication AND vault mounting are fully delegated to
    `spp-cli auth-mount`, which enforces the configured auth method
    cryptographically before unlocking the vault.  The bash script
    has no access to passwords or passphrases.
    """
    ensure_dirs()

    app_id   = app_config["id"]
    safe_id  = app_id.replace(":", "_").replace("/", "_")
    app_name = app_config.get("name", app_id)
    launch_cmd = app_config["launch_cmd"]
    encrypt  = app_config.get("encrypt_data", False)
    vault_path = app_config.get("vault_path", "")

    bash_name   = app_name.replace("'", "'\\''")
    bash_app_id = app_id.replace("'", "'\\''")

    script_path = SPP_WRAPPER_DIR / f"{safe_id}.sh"

    mount_section   = ""
    unmount_section = ""
    if encrypt and vault_path:
        mount_section = f"""
# Authenticate user and unlock vault (auth enforced cryptographically)
if ! spp-cli auth-mount '{bash_app_id}'; then
    zenity --error --title="SPPLoginMaster" \\
        --text="❌ Authentication failed.\\n$APP_NAME access denied."
    exit 1
fi
"""
        unmount_section = f"""
# Lock vault when the app exits
spp-cli unmount '{bash_app_id}' 2>/dev/null
"""

    script_content = f"""#!/bin/bash
# SPPLoginMaster wrapper for {bash_name}
# Auto-generated — do not edit manually.
# Authentication and decryption are handled by spp-cli auth-mount.

APP_NAME='{bash_name}'

{mount_section}
# Launch application
{launch_cmd}
APP_EXIT=$?
{unmount_section}
exit $APP_EXIT
"""

    script_path.write_text(script_content)
    script_path.chmod(0o755)
    return script_path


def patch_desktop_file(app_config: dict, wrapper_script: Path) -> bool:
    """Copy and patch the .desktop file to use our wrapper."""
    ensure_dirs()

    app_id = app_config["id"]
    safe_id = app_id.replace(":", "_").replace("/", "_")
    original_desktop = app_config.get("desktop_file")
    app_name = app_config.get("name", app_id)

    dest_desktop = DESKTOP_DIR / f"spp_{safe_id}.desktop"

    if original_desktop and Path(original_desktop).exists():
        shutil.copy(original_desktop, dest_desktop)
        content = dest_desktop.read_text()
        lines = content.splitlines()
        new_lines = []
        for line in lines:
            if line.startswith("Exec="):
                new_lines.append(f"Exec={wrapper_script}")
            elif line.startswith("Name=") and "=" not in line[5:6]:
                # Only replace the unlocalized Name= line
                new_lines.append(f"Name={app_name} [SPP]")
            elif line.startswith(("OnlyShowIn=", "NotShowIn=",
                                   "NoDisplay=", "Hidden=")):
                # Remove visibility restrictions so the app appears in GNOME
                pass
            else:
                new_lines.append(line)
        dest_desktop.write_text("\n".join(new_lines))
    else:
        # Create a minimal .desktop file
        dest_desktop.write_text(f"""[Desktop Entry]
Version=1.0
Type=Application
Name={app_name} [SPP]
Comment=Protected by SPPLoginMaster - Francesco Sappa
Exec={wrapper_script}
Terminal=false
Categories=Application;
""")

    subprocess.run(
        ["update-desktop-database", str(DESKTOP_DIR)],
        capture_output=True
    )
    return dest_desktop.exists()


def remove_desktop_file(app_id: str) -> bool:
    """Remove SPP wrapper desktop file."""
    safe_id = app_id.replace(":", "_").replace("/", "_")
    dest_desktop = DESKTOP_DIR / f"spp_{safe_id}.desktop"
    wrapper = SPP_WRAPPER_DIR / f"{safe_id}.sh"

    removed = False
    if dest_desktop.exists():
        dest_desktop.unlink()
        removed = True
    if wrapper.exists():
        wrapper.unlink()

    subprocess.run(
        ["update-desktop-database", str(DESKTOP_DIR)],
        capture_output=True
    )
    return removed
