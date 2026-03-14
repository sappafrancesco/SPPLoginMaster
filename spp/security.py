"""
SPPLoginMaster - Core Security Engine

Crypto model:
  Password / Both mode:
    passphrase = PBKDF2-HMAC-SHA256(user_password, per-app salt, 600 000 iters)
    The passphrase is NEVER stored. Without the correct password the vault
    keyfile is mathematically impossible to decrypt.

  Fingerprint mode:
    A cryptographically-random 32-byte passphrase is generated at protect time.
    It is stored in the GNOME keyring (libsecret / secret-tool), which is
    unlocked only by the user's login session.
    Decryption requires: valid fingerprint scan AND an unlocked login session.

  The vault keyfile is encrypted with GPG symmetric AES-256 using the
  passphrase above.  Without the correct passphrase gocryptfs cannot mount.
"""

import hashlib
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from spp.config import CONFIG_DIR


REQUIRED_BINS = [
    "fprintd-verify",
    "gpg",
    "gocryptfs",
    "fusermount",
    "zenity",
    "secret-tool",   # libsecret-tools — keyring access for fingerprint mode
    "pamtester",     # PAM password verification
]


# ── Dependencies ──────────────────────────────────────────────────────────────

def check_dependencies() -> list[str]:
    return [b for b in REQUIRED_BINS if not shutil.which(b)]


def install_dependencies() -> bool:
    pkgs = {
        "fprintd-verify": "fprintd",
        "gocryptfs":      "gocryptfs",
        "fusermount":     "fuse",
        "zenity":         "zenity",
        "gpg":            "gnupg2",
        "secret-tool":    "libsecret-tools",
        "pamtester":      "pamtester",
    }
    missing = check_dependencies()
    if not missing:
        return True
    to_install = list({pkgs[m] for m in missing if m in pkgs})
    # Use pkexec for a graphical PolicyKit privilege prompt (works from GUI).
    # Fall back to sudo if pkexec is not available (terminal context).
    elevator = "pkexec" if shutil.which("pkexec") else "sudo"
    return subprocess.run(
        [elevator, "apt", "install", "-y"] + to_install,
    ).returncode == 0


# ── Passphrase derivation (password mode) ────────────────────────────────────

def generate_salt() -> bytes:
    """32-byte cryptographically-random salt."""
    return secrets.token_bytes(32)


def derive_passphrase(password: str, salt: bytes) -> str:
    """
    PBKDF2-HMAC-SHA256, 600 000 iterations (NIST SP 800-132 2023).
    Returns a 64-char hex string used as GPG passphrase.
    Without the correct password this value cannot be reproduced.
    """
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000, dklen=32)
    return key.hex()


# ── GNOME Keyring via secret-tool (fingerprint mode) ─────────────────────────

def keyring_store(app_id: str, passphrase: str) -> bool:
    """Store passphrase in the user's GNOME keyring."""
    r = subprocess.run(
        ["secret-tool", "store",
         "--label", f"SPPLoginMaster: {app_id}",
         "application", "spploginmaster",
         "app-id", app_id],
        input=passphrase.encode(),
        capture_output=True,
    )
    return r.returncode == 0


def keyring_get(app_id: str) -> str | None:
    """Retrieve passphrase from GNOME keyring. Returns None if not found."""
    r = subprocess.run(
        ["secret-tool", "lookup",
         "application", "spploginmaster",
         "app-id", app_id],
        capture_output=True, text=True,
    )
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def keyring_delete(app_id: str):
    """Remove passphrase from GNOME keyring."""
    subprocess.run(
        ["secret-tool", "clear",
         "application", "spploginmaster",
         "app-id", app_id],
        capture_output=True,
    )


# ── Symmetric GPG encryption (AES-256 with passphrase) ───────────────────────

def _pp_tmpfile(passphrase: str) -> str:
    """Write passphrase to a 0600 temp file, return path. Caller must shred."""
    tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".pp")
    tmp.write(passphrase)
    tmp.close()
    os.chmod(tmp.name, 0o600)
    return tmp.name


def create_encrypted_keyfile(app_id: str, passphrase: str) -> Path | None:
    """
    Generate a random gocryptfs key and encrypt it with GPG symmetric AES-256.
    S2K: iterated+salted SHA-512, 65 011 712 iterations.
    The file can ONLY be decrypted with the exact same passphrase.
    """
    keyfile_plain = CONFIG_DIR / f"{app_id}.key.plain"
    keyfile_gpg   = CONFIG_DIR / f"{app_id}.key.gpg"
    pp_file = None

    # Random vault key: 64 hex chars (256 bits of entropy) + newline
    keyfile_plain.write_bytes(secrets.token_hex(32).encode() + b"\n")
    keyfile_plain.chmod(0o600)

    try:
        pp_file = _pp_tmpfile(passphrase)
        result = subprocess.run(
            ["gpg", "--batch", "--no-tty", "--yes",
             "--symmetric",
             "--cipher-algo", "AES256",
             "--s2k-digest-algo", "SHA512",
             "--s2k-mode", "3",
             "--s2k-count", "65011712",
             "--passphrase-file", pp_file,
             "--output", str(keyfile_gpg),
             str(keyfile_plain)],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and keyfile_gpg.exists():
            keyfile_gpg.chmod(0o600)
            return keyfile_gpg
    except Exception as e:
        print(f"Keyfile creation error: {e}")
    finally:
        for f in [str(keyfile_plain), pp_file]:
            if f and Path(f).exists():
                subprocess.run(["shred", "-u", f], capture_output=True)

    if keyfile_gpg.exists():
        keyfile_gpg.unlink()
    return None


def decrypt_keyfile_to_tempfile(app_id: str, passphrase: str) -> str | None:
    """
    Decrypt the GPG-encrypted keyfile using passphrase.
    Returns path to a 0600 temp file with the plaintext key.
    Caller MUST shred this file after use.
    """
    keyfile_gpg = CONFIG_DIR / f"{app_id}.key.gpg"
    if not keyfile_gpg.exists():
        return None

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
    tmp.close()
    os.chmod(tmp.name, 0o600)

    pp_file = None
    try:
        pp_file = _pp_tmpfile(passphrase)
        result = subprocess.run(
            ["gpg", "--batch", "--no-tty", "--yes",
             "--decrypt",
             "--passphrase-file", pp_file,
             "--output", tmp.name,
             str(keyfile_gpg)],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return tmp.name
    except Exception:
        pass
    finally:
        if pp_file and Path(pp_file).exists():
            subprocess.run(["shred", "-u", pp_file], capture_output=True)

    subprocess.run(["shred", "-u", tmp.name], capture_output=True)
    return None


# ── Fingerprint ───────────────────────────────────────────────────────────────

def _fprintd_recover(attempt: int):
    """
    Escalating recovery for a stuck fprintd device.

    attempt 0 : kill stale fprintd-verify CLI processes
    attempt 3 : also kill any fprintd D-Bus helper processes
    attempt 5 : restart the fprintd systemd service
                (tries sudo -n first, then pkexec for GUI auth)
    """
    import time

    # Always: kill the fprintd-verify CLI helper (our old code path)
    subprocess.run(["pkill", "-x", "fprintd-verify"], capture_output=True)

    if attempt >= 3:
        # Kill broader fprintd-related processes
        subprocess.run(["pkill", "-f", "fprintd-verify"], capture_output=True)
        print(f"[SPP] fprintd recover: aggressive pkill (attempt {attempt})")

    if attempt >= 5:
        print("[SPP] fprintd recover: restarting fprintd service…")
        # Try without password (works if user has NOPASSWD or polkit allows it)
        r = subprocess.run(
            ["sudo", "-n", "systemctl", "restart", "fprintd"],
            capture_output=True, timeout=10,
        )
        if r.returncode != 0 and shutil.which("pkexec"):
            # Fallback: pkexec shows a GUI polkit auth dialog
            subprocess.run(
                ["pkexec", "systemctl", "restart", "fprintd"],
                capture_output=True, timeout=30,
            )
        time.sleep(2)   # Give the daemon time to come back up


def verify_fingerprint(username: str) -> bool:
    """
    Verify fingerprint via fprintd D-Bus.

    Handles AlreadyInUse with escalating auto-recovery:
      - Retries 1-2 : pkill stale fprintd-verify processes + backoff
      - Retries 3-4 : broader process cleanup
      - Retry   5+  : restart fprintd service (sudo -n / pkexec)
    Total timeout: 35 s.
    """
    import time

    deadline = time.monotonic() + 35
    backoff  = 1.0
    attempt  = 0

    while time.monotonic() < deadline:
        _fprintd_recover(attempt)

        remaining = deadline - time.monotonic()
        result    = _fprintd_verify_once(username, remaining)
        if result is not None:
            return result

        # AlreadyInUse — wait then escalate
        attempt += 1
        wait = min(backoff, deadline - time.monotonic())
        if wait <= 0:
            break
        time.sleep(wait)
        backoff = min(backoff * 1.5, 5.0)

    return False


def _fprintd_verify_once(username: str, timeout_secs: float):
    """
    Single fprintd Claim→VerifyStart→wait→Release cycle.

    Returns:
      True   – verify-match
      False  – definitive failure (no-match, scan error, timeout)
      None   – AlreadyInUse (caller should retry after a delay)
    """
    try:
        from gi.repository import Gio, GLib
    except ImportError:
        return False

    if timeout_secs <= 0:
        return False

    ctx            = GLib.MainContext.new()
    ctx.push_thread_default()
    loop           = GLib.MainLoop.new(ctx, False)
    matched        = [None]
    dev_ref        = [None]
    claimed        = [False]
    verify_started = [False]
    busy           = [False]

    def _release():
        if dev_ref[0] is None:
            return
        if verify_started[0]:
            try:
                dev_ref[0].call_sync(
                    "VerifyStop", None, Gio.DBusCallFlags.NONE, -1, None
                )
            except Exception:
                pass
            verify_started[0] = False
        if claimed[0]:
            try:
                dev_ref[0].call_sync(
                    "Release", None, Gio.DBusCallFlags.NONE, -1, None
                )
            except Exception:
                pass
            claimed[0] = False

    def on_signal(proxy, _sender, signal_name, params):
        if signal_name == "VerifyStatus":
            status, done = params.unpack()
            if done:
                matched[0] = (status == "verify-match")
                verify_started[0] = False
                _release()
                loop.quit()

    try:
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

        mgr = Gio.DBusProxy.new_sync(
            bus, Gio.DBusProxyFlags.NONE, None,
            "net.reactivated.Fprint",
            "/net/reactivated/Fprint/Manager",
            "net.reactivated.Fprint.Manager",
            None,
        )
        dev_path = mgr.call_sync(
            "GetDefaultDevice", None, Gio.DBusCallFlags.NONE, -1, None
        ).unpack()[0]

        dev = Gio.DBusProxy.new_sync(
            bus, Gio.DBusProxyFlags.NONE, None,
            "net.reactivated.Fprint", dev_path,
            "net.reactivated.Fprint.Device", None,
        )
        dev_ref[0] = dev
        dev.connect("g-signal", on_signal)

        dev.call_sync(
            "Claim",
            GLib.Variant("(s)", (username or "",)),
            Gio.DBusCallFlags.NONE, -1, None,
        )
        claimed[0] = True

        dev.call_sync(
            "VerifyStart",
            GLib.Variant("(s)", ("any",)),
            Gio.DBusCallFlags.NONE, -1, None,
        )
        verify_started[0] = True

        GLib.timeout_add_seconds(int(timeout_secs), lambda: loop.quit() or False)
        loop.run()

    except Exception as e:
        if "AlreadyInUse" in str(e):
            busy[0] = True
        else:
            print(f"[SPP] fingerprint error: {e}")
    finally:
        _release()
        ctx.pop_thread_default()

    if busy[0]:
        return None             # signal: device busy, caller should retry
    return matched[0] is True   # True=match, False=no-match/timeout


def is_fingerprint_available() -> bool:
    try:
        r = subprocess.run(
            ["fprintd-list", os.environ.get("USER", "")],
            capture_output=True, text=True, timeout=5,
        )
        return "finger" in r.stdout.lower()
    except Exception:
        return False


# ── Password / PAM ────────────────────────────────────────────────────────────

def verify_password_pam(username: str, password: str) -> bool:
    """Verify password against PAM via pamtester."""
    try:
        r = subprocess.run(
            ["pamtester", "login", username, "authenticate"],
            input=password.encode(),
            capture_output=True,
            timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


# ── gocryptfs ─────────────────────────────────────────────────────────────────

def init_encrypted_vault(app_id: str, vault_path: Path, passphrase: str) -> bool:
    tmp_key = decrypt_keyfile_to_tempfile(app_id, passphrase)
    if not tmp_key:
        return False
    vault_path.mkdir(parents=True, exist_ok=True)
    try:
        r = subprocess.run(
            ["gocryptfs", "-init", "-passfile", tmp_key, str(vault_path)],
            capture_output=True, text=True,
        )
        return r.returncode == 0
    finally:
        if os.path.exists(tmp_key):
            subprocess.run(["shred", "-u", tmp_key], capture_output=True)


def mount_vault(app_id: str, vault_path: Path, mount_path: Path, passphrase: str) -> bool:
    tmp_key = decrypt_keyfile_to_tempfile(app_id, passphrase)
    if not tmp_key:
        return False
    mount_path.mkdir(parents=True, exist_ok=True)
    try:
        r = subprocess.run(
            ["gocryptfs", "-passfile", tmp_key, str(vault_path), str(mount_path)],
            capture_output=True, text=True,
        )
        return r.returncode == 0
    finally:
        if os.path.exists(tmp_key):
            subprocess.run(["shred", "-u", tmp_key], capture_output=True)


def unmount_vault(mount_path: Path) -> bool:
    return subprocess.run(
        ["fusermount", "-u", str(mount_path)],
        capture_output=True,
    ).returncode == 0


def is_mounted(mount_path: Path) -> bool:
    return subprocess.run(
        ["mountpoint", "-q", str(mount_path)],
        capture_output=True,
    ).returncode == 0


def unmount_all() -> list[tuple[str, bool]]:
    from spp.config import list_apps
    return [
        (app["id"], unmount_vault(Path(app["mount_path"])))
        for app in list_apps()
        if app.get("mount_path") and is_mounted(Path(app["mount_path"]))
    ]
