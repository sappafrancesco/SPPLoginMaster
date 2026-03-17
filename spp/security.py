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

import time

from spp.config import CONFIG_DIR, safe_filename


REQUIRED_BINS = [
    "fprintd-verify",
    "gpg",
    "gocryptfs",
    "fusermount",
    "zenity",
    "secret-tool",   # libsecret-tools — keyring access for fingerprint mode
    # pamtester removed: password verification uses libpam directly via ctypes
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
    """
    Store passphrase in the user's GNOME keyring.
    Verifies the stored value with an immediate lookup to catch silent failures
    (e.g. keyring daemon restarted, session mismatch).
    """
    r = subprocess.run(
        ["secret-tool", "store",
         "--label", f"SPPLoginMaster: {app_id}",
         "application", "spploginmaster",
         "app-id", app_id],
        input=passphrase.encode(),
        capture_output=True,
    )
    if r.returncode != 0:
        return False
    # Verify the secret was actually persisted
    stored = keyring_get(app_id)
    return stored == passphrase


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

# Module-level: track open memfds so their fd numbers stay valid [SPP-01, SPP-07]
_open_memfds: dict[str, int] = {}


def _pp_tmpfile(passphrase: str) -> str:
    """
    Write passphrase to a Linux memfd (anonymous in-memory file descriptor).
    Returns '/proc/self/fd/<n>' — never written to disk, immune to
    wear-levelling leaks on SSDs and copy-on-write filesystems. [SPP-01, SPP-07]

    Falls back to a 0600 temp file if memfd_create is unavailable.
    """
    try:
        import ctypes as _ct
        _libc = _ct.CDLL(None)
        _libc.memfd_create.restype  = _ct.c_int
        _libc.memfd_create.argtypes = [_ct.c_char_p, _ct.c_uint]
        fd = _libc.memfd_create(b"spp-pp", 0)
        if fd >= 0:
            os.write(fd, passphrase.encode())
            # Use the absolute PID path so child processes (e.g. gpg) can also
            # access it via /proc/<parent-pid>/fd/<n>.  /proc/self/fd/<n> would
            # resolve to the *child's* fd table instead of ours.
            path = f"/proc/{os.getpid()}/fd/{fd}"
            _open_memfds[path] = fd
            return path
    except Exception:
        pass

    # Fallback: 0600 tempfile
    tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".pp")
    tmp.write(passphrase)
    tmp.close()
    os.chmod(tmp.name, 0o600)
    return tmp.name


def _pp_cleanup(path: str | None):
    """Close a memfd or shred a tmpfile created by _pp_tmpfile."""
    if not path:
        return
    if path in _open_memfds:
        try:
            os.close(_open_memfds.pop(path))
        except OSError:
            pass
        return
    if Path(path).exists():
        subprocess.run(["shred", "-u", path], capture_output=True)


def create_encrypted_keyfile(app_id: str, passphrase: str) -> Path | None:
    """
    Generate a random gocryptfs key and encrypt it with GPG symmetric AES-256.
    S2K: iterated+salted SHA-512, 65 011 712 iterations.
    The file can ONLY be decrypted with the exact same passphrase.
    """
    sfid = safe_filename(app_id)
    keyfile_plain = CONFIG_DIR / f"{sfid}.key.plain"
    keyfile_gpg   = CONFIG_DIR / f"{sfid}.key.gpg"
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
        _pp_cleanup(pp_file)
        if keyfile_plain.exists():
            subprocess.run(["shred", "-u", str(keyfile_plain)], capture_output=True)

    if keyfile_gpg.exists():
        keyfile_gpg.unlink()
    return None


def decrypt_keyfile_to_tempfile(app_id: str, passphrase: str) -> str | None:
    """
    Decrypt the GPG-encrypted keyfile using passphrase.
    Returns path to a 0600 temp file with the plaintext key.
    Caller MUST shred this file after use.
    """
    sfid = safe_filename(app_id)
    keyfile_gpg = CONFIG_DIR / f"{sfid}.key.gpg"
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
        _pp_cleanup(pp_file)

    subprocess.run(["shred", "-u", tmp.name], capture_output=True)
    return None


# ── Fingerprint ───────────────────────────────────────────────────────────────

def _fprintd_recover(attempt: int):
    """
    Escalating recovery for a stuck fprintd device.

    attempt 0 : kill stale fprintd-verify CLI processes
    attempt 3 : broader pkill + udevadm USB re-probe
    attempt 5 : restart the fprintd systemd service
                (tries sudo -n first, then pkexec for GUI auth)
    """
    import time

    # Kill only OUR OWN stale fprintd-verify processes — filter by UID [SPP-09]
    _uid = str(os.getuid())
    subprocess.run(["pkill", "--euid", _uid, "-x", "fprintd-verify"], capture_output=True)

    if attempt >= 3:
        subprocess.run(["pkill", "--euid", _uid, "-f", "fprintd-verify"], capture_output=True)
        # Re-probe USB devices — often unblocks a frozen sensor without root
        subprocess.run(
            ["udevadm", "trigger", "--subsystem-match=usb"],
            capture_output=True, timeout=5,
        )
        print(f"[SPP] fprintd recover: pkill + udevadm (attempt {attempt})")

    if attempt >= 5:
        print("[SPP] fprintd recover: restarting fprintd service…")
        r = subprocess.run(
            ["sudo", "-n", "systemctl", "restart", "fprintd"],
            capture_output=True, timeout=10,
        )
        if r.returncode != 0 and shutil.which("pkexec"):
            subprocess.run(
                ["pkexec", "systemctl", "restart", "fprintd"],
                capture_output=True, timeout=30,
            )
        time.sleep(2)   # give the daemon time to come back up


def verify_fingerprint(username: str, status_cb=None) -> bool:
    """
    Verify fingerprint via fprintd D-Bus.

    Escalating auto-recovery for a stuck/crashed sensor:
      - Retries 1-2 : pkill stale fprintd-verify processes + backoff
      - Retries 3-4 : broader pkill + udevadm USB re-probe
      - Retry   5+  : restart fprintd service (sudo -n / pkexec)
    Total timeout: 35 s.

    status_cb(msg): optional callable, called with a human-readable string
                    whenever recovery kicks in so the UI can update.
    """
    import time

    deadline = time.monotonic() + 35
    backoff  = 1.0
    attempt  = 0

    while time.monotonic() < deadline:
        if attempt > 0 and status_cb:
            if attempt >= 5:
                status_cb("Restarting fingerprint sensor…")
            else:
                status_cb("Sensor error — retrying…")

        _fprintd_recover(attempt)

        remaining = deadline - time.monotonic()
        result    = _fprintd_verify_once(username, remaining)

        if result is True:
            return True
        if result is False:
            # Definitive: sensor responded with verify-no-match
            return False

        # result is None: recoverable (AlreadyInUse, sensor crash, timeout)
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
      True   – verify-match (definitive success)
      False  – verify-no-match (definitive failure: wrong finger)
      None   – recoverable: AlreadyInUse, sensor error, timeout with no
               response, or any unexpected exception — caller should
               run _fprintd_recover() and retry.
    """
    try:
        from gi.repository import Gio, GLib
    except ImportError:
        return False

    if timeout_secs <= 0:
        return None

    ctx            = GLib.MainContext.new()
    ctx.push_thread_default()
    loop           = GLib.MainLoop.new(ctx, False)
    matched        = [None]   # True | False | None
    dev_ref        = [None]
    claimed        = [False]
    verify_started = [False]
    recoverable    = [False]  # set for AlreadyInUse, sensor errors, timeout

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
        if signal_name != "VerifyStatus":
            return
        status, done = params.unpack()
        if not done:
            # Intermediate hints (retry-scan, swipe-too-short, etc.) —
            # fprintd keeps the scan running, just wait for the next signal.
            return
        if status == "verify-match":
            matched[0] = True
        elif status == "verify-no-match":
            matched[0] = False          # definitive: wrong finger
        else:
            # verify-unknown-error, verify-disconnected — sensor crashed
            recoverable[0] = True
        verify_started[0] = False
        _release()
        loop.quit()

    def _on_timeout():
        # No VerifyStatus signal arrived before the deadline.
        # The sensor is hung — mark as recoverable so the caller retries.
        recoverable[0] = True
        loop.quit()
        return False  # don't repeat

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

        GLib.timeout_add_seconds(int(timeout_secs), _on_timeout)
        loop.run()

    except Exception as e:
        err = str(e)
        if "AlreadyInUse" in err:
            recoverable[0] = True
        elif any(k in err for k in ("NoEnrolledPrints", "NoSuchDevice")):
            # Permanent conditions — don't bother retrying
            print(f"[SPP] fingerprint unavailable: {e}")
            return False
        else:
            # Unknown D-Bus / GLib error — treat as recoverable
            print(f"[SPP] fingerprint error: {e}")
            recoverable[0] = True
    finally:
        _release()
        ctx.pop_thread_default()

    if recoverable[0]:
        return None   # caller should run recovery and retry
    if matched[0] is True:
        return True
    if matched[0] is False:
        return False
    # matched is still None (loop quit for an unexpected reason) → recoverable
    return None


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

# Per-username lockout state for brute-force protection [SPP-05]
_pam_lockout: dict[str, tuple[int, float]] = {}  # username -> (fail_count, locked_until)


def verify_password_pam(username: str, password: str) -> bool:
    """
    Verify password via libpam directly (ctypes).

    Calling pamtester via subprocess fails silently: pamtester uses
    pam_misc_conv which calls tcgetattr(stdin) to disable echo — when stdin
    is a PIPE (not a tty) tcgetattr returns ENOTTY, the conversation bails,
    and PAM receives an empty password regardless of what was sent.

    Calling libpam directly with our own conversation function bypasses stdin
    entirely and supplies the password in-process.

    Rate limiting: exponential backoff after repeated failures. [SPP-05]
    """
    # ── Rate limiting check [SPP-05] ──────────────────────────────────
    fail_count, locked_until = _pam_lockout.get(username, (0, 0.0))
    now = time.monotonic()
    if now < locked_until:
        remaining = int(locked_until - now)
        print(f"[SPP] PAM: {username} locked for {remaining}s more")
        return False

    try:
        import ctypes, ctypes.util

        libpam = ctypes.CDLL(ctypes.util.find_library("pam"))
        libc   = ctypes.CDLL(None)
        libc.malloc.restype  = ctypes.c_void_p
        libc.malloc.argtypes = [ctypes.c_size_t]
        libc.strdup.restype  = ctypes.c_void_p
        libc.strdup.argtypes = [ctypes.c_char_p]

        PAM_SUCCESS         = 0
        PAM_PROMPT_ECHO_OFF = 1

        class _pam_message(ctypes.Structure):
            _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]

        class _pam_response(ctypes.Structure):
            _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]

        _CONV_FUNC = ctypes.CFUNCTYPE(
            ctypes.c_int,
            ctypes.c_int,
            ctypes.POINTER(ctypes.POINTER(_pam_message)),
            ctypes.POINTER(ctypes.POINTER(_pam_response)),
            ctypes.c_void_p,
        )

        class _pam_conv(ctypes.Structure):
            _fields_ = [("conv", _CONV_FUNC), ("appdata_ptr", ctypes.c_void_p)]

        pw_bytes = password.encode()

        @_CONV_FUNC
        def _conv(n_msg, msg_list, resp_list, _appdata):
            # PAM will free() both the array and each resp string,
            # so everything must be malloc-allocated (not Python heap).
            arr_ptr = libc.malloc(ctypes.sizeof(_pam_response) * n_msg)
            if not arr_ptr:
                return 1
            ctypes.memset(arr_ptr, 0, ctypes.sizeof(_pam_response) * n_msg)
            responses = (_pam_response * n_msg).from_address(arr_ptr)
            for i in range(n_msg):
                if msg_list[i].contents.msg_style == PAM_PROMPT_ECHO_OFF:
                    responses[i].resp = libc.strdup(pw_bytes)
            resp_list[0] = ctypes.cast(arr_ptr, ctypes.POINTER(_pam_response))
            return PAM_SUCCESS

        conv   = _pam_conv(_conv, None)
        handle = ctypes.c_void_p()
        libpam.pam_start(
            b"login", username.encode(),
            ctypes.byref(conv), ctypes.byref(handle),
        )
        ret = libpam.pam_authenticate(handle, 0)
        libpam.pam_end(handle, ret)

        if ret == PAM_SUCCESS:
            _pam_lockout.pop(username, None)   # reset on success
            return True

        # ── Update lockout on failure [SPP-05] ────────────────────────
        fail_count += 1
        wait = min(2 ** (fail_count - 1), 300)  # 1, 2, 4, 8 … 300 s
        _pam_lockout[username] = (fail_count, time.monotonic() + wait)
        return False

    except Exception as e:
        print(f"[SPP] PAM error: {e}")
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

    # TOCTOU guard: verify mount_path is a real directory, not a symlink. [SPP-03]
    # An attacker could replace it with a symlink between mkdir and mount,
    # redirecting the vault mount to an arbitrary directory.
    try:
        _fd = os.open(str(mount_path), os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
        os.close(_fd)
    except OSError:
        print(f"[SPP] TOCTOU: mount_path is a symlink or not a directory: {mount_path}")
        return False

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
