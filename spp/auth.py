"""
SPPLoginMaster - Authentication Orchestration

This module is the ONLY place that combines identity verification (fingerprint /
PAM password) with passphrase retrieval.  No other module can obtain a
passphrase without going through here.

Security guarantees:
  • password / both modes:  passphrase = PBKDF2(password, salt).
    Without the correct password the passphrase cannot be reproduced.
  • fingerprint mode: passphrase is retrieved from the GNOME keyring.
    Keyring access requires an authenticated login session, AND a successful
    fprintd fingerprint scan is required before the lookup is attempted.
"""

import os
import subprocess

from spp.config import get_app_config, get_app_salt
from spp.security import (
    verify_fingerprint,
    verify_password_pam,
    derive_passphrase,
    keyring_get,
)


def get_passphrase(app_id: str, password: str | None = None) -> str | None:
    """
    Verify the user's identity according to the app's auth_method, then
    return the decryption passphrase.

    Parameters
    ----------
    app_id   : registered app identifier
    password : plaintext password supplied by the caller (required for
               'password' and 'both' modes; ignored for 'fingerprint')

    Returns
    -------
    passphrase string on success, None on any auth failure.
    The passphrase is derived fresh — it is NEVER cached or stored.
    """
    config = get_app_config(app_id)
    if not config:
        return None

    auth_method = config.get("auth_method", "fingerprint")
    username     = config.get("username", os.environ.get("USER", ""))

    # ── Step 1 : fingerprint verification (if required) ───────────────
    if auth_method in ("fingerprint", "both"):
        if not verify_fingerprint(username):
            return None

    # ── Step 2 : password verification + passphrase derivation ───────
    if auth_method in ("password", "both"):
        if not password:
            return None
        if not verify_password_pam(username, password):
            return None
        salt = get_app_salt(app_id)
        if not salt:
            return None
        return derive_passphrase(password, salt)

    # ── Fingerprint-only: retrieve from keyring ────────────────────────
    if auth_method == "fingerprint":
        return keyring_get(app_id)

    return None


def get_passphrase_interactive(app_id: str) -> str | None:
    """
    Show a graphical GTK4/libadwaita auth dialog with live feedback.
    Falls back to zenity if GTK is unavailable.
    Used by wrapper scripts launched from .desktop files.
    """
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from spp.auth_dialog import run_auth_dialog
        return run_auth_dialog(app_id)
    except Exception as e:
        import sys
        print(f"[SPP] GUI auth unavailable ({e}), falling back to zenity", file=sys.stderr)
        return _get_passphrase_zenity(app_id)


def _get_passphrase_zenity(app_id: str) -> str | None:
    """Zenity fallback for environments without a display or GTK."""
    config = get_app_config(app_id)
    if not config:
        return None

    auth_method = config.get("auth_method", "fingerprint")
    app_name    = config.get("name", app_id)
    password    = None

    if auth_method in ("fingerprint", "both"):
        info = subprocess.Popen(
            ["zenity", "--info", "--title=SPPLoginMaster",
             f"--text=👆  Place your finger on the sensor\nto unlock <b>{app_name}</b>",
             "--timeout=35"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        username = config.get("username", os.environ.get("USER", ""))
        ok = verify_fingerprint(username)
        info.terminate()
        if not ok:
            subprocess.run(
                ["zenity", "--error", "--title=SPPLoginMaster",
                 f"--text=❌  Fingerprint not recognised.\n{app_name} access denied."],
                capture_output=True,
            )
            return None

    if auth_method in ("password", "both"):
        r = subprocess.run(
            ["zenity", "--password", f"--title=SPPLoginMaster — {app_name}"],
            capture_output=True, text=True,
        )
        if r.returncode != 0 or not r.stdout.strip():
            subprocess.run(
                ["zenity", "--error", "--title=SPPLoginMaster",
                 f"--text=❌  No password entered.\n{app_name} access denied."],
                capture_output=True,
            )
            return None
        password = r.stdout.strip()

    return get_passphrase(app_id, password=password)
