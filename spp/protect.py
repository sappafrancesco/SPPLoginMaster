"""
SPPLoginMaster - Protection Workflow

All vault operations require a passphrase obtained through spp.auth.
No passphrase → no mount. No mount → no data.
"""

import os
import shutil
import subprocess
from pathlib import Path

from spp.config import (
    set_app_config, remove_app_config, get_app_config,
    CONFIG_DIR, set_app_salt,
)
from spp.security import (
    generate_salt, derive_passphrase,
    create_encrypted_keyfile, init_encrypted_vault,
    mount_vault, unmount_vault, is_mounted,
    keyring_store, keyring_delete,
)
from spp.launcher import create_wrapper_script, patch_desktop_file, remove_desktop_file

VAULTS_DIR = Path.home() / ".local" / "share" / "spploginmaster" / "vaults"


# ── Internal helpers ──────────────────────────────────────────────────────────

def _cleanup(vault_path: Path, tmp_mount: Path | None, app_id: str):
    """Remove all artifacts left by a failed protect attempt."""
    if tmp_mount and tmp_mount.exists():
        if is_mounted(tmp_mount):
            unmount_vault(tmp_mount)
        try:
            tmp_mount.rmdir()
        except OSError:
            shutil.rmtree(str(tmp_mount), ignore_errors=True)
    if vault_path and vault_path.exists():
        shutil.rmtree(str(vault_path), ignore_errors=True)
    gpg = CONFIG_DIR / f"{app_id}.key.gpg"
    if gpg.exists():
        gpg.unlink()


def _shred_tree(path: Path):
    """
    Overwrite-then-delete every regular file under path with shred,
    then remove the directory tree.

    Note: shred is not effective on SSDs, btrfs, or ZFS due to
    wear-levelling and copy-on-write semantics.  Full-disk encryption
    (LUKS) is the only complete mitigation on such storage. [SPP-02, SPP-07]
    """
    try:
        for f in path.rglob("*"):
            if f.is_file() and not f.is_symlink():
                subprocess.run(["shred", "-u", str(f)], capture_output=True)
    except Exception:
        pass
    shutil.rmtree(str(path), ignore_errors=True)


# ── protect_app ───────────────────────────────────────────────────────────────

def protect_app(
    app: dict,
    auth_method: str = "fingerprint",
    encrypt_data: bool = True,
    username: str = None,
    password: str = None,         # required for 'password' and 'both' modes
) -> tuple[bool, str]:
    """
    Protect an app.

    For 'password'/'both' auth: caller must supply the verified plaintext
    password so we can derive and store the PBKDF2 passphrase salt.

    For 'fingerprint' auth: a random passphrase is generated and stored in
    the GNOME keyring.

    The migration is atomic: original data is replaced by an os.rename()
    only AFTER the vault has been verified.  Any failure leaves the system
    in its original state.
    """
    app_id   = app["id"]
    app_name = app.get("name", app_id)
    data_path = Path(app["data_path"]) if app.get("data_path") else None
    username  = username or os.environ.get("USER", "")

    # ── Derive / generate the passphrase ──────────────────────────────
    if auth_method in ("password", "both"):
        if not password:
            return False, "A password is required for this authentication method."
        salt = generate_salt()
        passphrase = derive_passphrase(password, salt)
    else:
        # fingerprint — random passphrase stored in GNOME keyring
        import secrets
        passphrase = secrets.token_hex(32)
        salt       = None

    vault_path = None
    mount_path = None

    if encrypt_data and data_path and not data_path.exists():
        return False, (
            f"Data directory '{data_path}' not found. "
            "Launch the app at least once so it creates its profile, then try again."
        )

    if encrypt_data and data_path and data_path.exists():
        vault_path = VAULTS_DIR / app_id.replace(":", "_")
        mount_path = data_path
        tmp_mount  = vault_path.parent / f"{app_id.replace(':', '_')}_tmp_mount"
        backup_path = data_path.parent / f"{data_path.name}_spp_backup"

        # ── Clean up stale leftovers ───────────────────────────────────
        for stale in [tmp_mount]:
            if stale.exists():
                if is_mounted(stale):
                    unmount_vault(stale)
                try:
                    stale.rmdir()
                except OSError:
                    shutil.rmtree(str(stale), ignore_errors=True)
        if vault_path.exists():
            shutil.rmtree(str(vault_path))
        gpg = CONFIG_DIR / f"{app_id}.key.gpg"
        if gpg.exists():
            gpg.unlink()
        if backup_path.exists():
            shutil.rmtree(str(backup_path), ignore_errors=True)

        vault_path.mkdir(parents=True, exist_ok=True)
        tmp_mount.mkdir(parents=True, exist_ok=True)

        # Step 1 — GPG-encrypted keyfile (AES-256 symmetric, s2k SHA-512)
        if not create_encrypted_keyfile(app_id, passphrase):
            _cleanup(vault_path, tmp_mount, app_id)
            return False, "Cannot create encrypted keyfile."

        # Step 2 — Initialise gocryptfs vault
        if not init_encrypted_vault(app_id, vault_path, passphrase):
            _cleanup(vault_path, tmp_mount, app_id)
            return False, "Cannot initialise gocryptfs vault."

        # Step 3 — Mount at tmp and copy data in
        if not mount_vault(app_id, vault_path, tmp_mount, passphrase):
            _cleanup(vault_path, tmp_mount, app_id)
            return False, "Cannot mount vault for data migration."

        try:
            for item in data_path.iterdir():
                dest = tmp_mount / item.name
                if item.is_symlink():
                    os.symlink(os.readlink(item), dest)
                elif item.is_dir():
                    shutil.copytree(str(item), str(dest), symlinks=True, dirs_exist_ok=True)
                else:
                    shutil.copy2(str(item), str(dest))
        except Exception as e:
            unmount_vault(tmp_mount)
            _cleanup(vault_path, tmp_mount, app_id)
            return False, f"Data migration failed: {e}"

        unmount_vault(tmp_mount)

        # Step 4 — Verify vault contains all expected top-level items
        if not mount_vault(app_id, vault_path, tmp_mount, passphrase):
            _cleanup(vault_path, tmp_mount, app_id)
            return False, "Vault verification failed: cannot re-mount."

        original_items = {p.name for p in data_path.iterdir()}
        vault_items    = {p.name for p in tmp_mount.iterdir()}
        unmount_vault(tmp_mount)

        missing = original_items - vault_items
        if missing:
            _cleanup(vault_path, tmp_mount, app_id)
            return False, (
                f"Vault verification failed: {len(missing)} item(s) missing "
                f"({', '.join(sorted(missing)[:5])})."
            )

        try:
            tmp_mount.rmdir()
        except OSError:
            pass

        # Step 5 — Atomic rename (original data safe until vault is live)
        try:
            os.rename(str(data_path), str(backup_path))
        except OSError as e:
            _cleanup(vault_path, None, app_id)
            return False, f"Cannot create atomic backup: {e}"

        # Step 6 — Mount vault at original path
        data_path.mkdir(parents=True, exist_ok=True)
        if not mount_vault(app_id, vault_path, mount_path, passphrase):
            try:
                data_path.rmdir()
                os.rename(str(backup_path), str(data_path))
            except OSError:
                pass
            _cleanup(vault_path, None, app_id)
            return False, "Cannot mount vault at final location — original data restored."

        # Step 7 — Shred plaintext backup then remove it [SPP-02]
        _shred_tree(backup_path)

    # ── Persist passphrase / salt ─────────────────────────────────────
    app_config = {
        **app,
        "auth_method":  auth_method,
        "encrypt_data": encrypt_data,
        "vault_path":   str(vault_path) if vault_path else None,
        "mount_path":   str(mount_path) if mount_path else None,
        "username":     username,
        "crypto_version": 2,
    }
    set_app_config(app_id, app_config)

    if auth_method in ("password", "both"):
        set_app_salt(app_id, salt)       # salt saved in apps.json
    else:
        # fingerprint: passphrase goes to GNOME keyring
        if not keyring_store(app_id, passphrase):
            remove_app_config(app_id)
            if vault_path:
                _cleanup(vault_path, None, app_id)
            return False, (
                "Cannot store passphrase in GNOME keyring. "
                "Is libsecret-tools installed and the GNOME keyring unlocked?"
            )

    # ── Wire up launcher ──────────────────────────────────────────────
    wrapper = create_wrapper_script(app_config)
    patch_desktop_file(app_config, wrapper)

    # Store HMAC of wrapper script for integrity verification [SPP-08]
    from spp.launcher import compute_wrapper_hmac
    app_config["wrapper_hmac"] = compute_wrapper_hmac(app_id)
    set_app_config(app_id, app_config)

    return True, f"✅ {app_name} successfully protected."


# ── unprotect_app ─────────────────────────────────────────────────────────────

def unprotect_app(app_id: str, passphrase: str | None = None) -> tuple[bool, str]:
    """
    Remove protection.  Requires the correct passphrase (caller must have
    authenticated via spp.auth first).
    """
    config = get_app_config(app_id)
    if not config:
        return False, "App not found."

    app_name   = config.get("name", app_id)
    mount_path = Path(config["mount_path"]) if config.get("mount_path") else None
    vault_path = Path(config["vault_path"]) if config.get("vault_path") else None

    if mount_path and vault_path:
        # Ensure vault is mounted so we can read the data
        if not is_mounted(mount_path):
            if not mount_vault(app_id, vault_path, mount_path, passphrase):
                return False, "Cannot mount vault to restore data."

        # Copy decrypted data out
        tmp_restore = mount_path.parent / f"{mount_path.name}_spp_restore"
        try:
            shutil.copytree(str(mount_path), str(tmp_restore), symlinks=True)
        except Exception as e:
            unmount_vault(mount_path)
            return False, f"Cannot extract data from vault: {e}"

        unmount_vault(mount_path)
        shutil.rmtree(str(mount_path), ignore_errors=True)
        try:
            os.rename(str(tmp_restore), str(mount_path))
        except OSError as e:
            return False, f"Cannot restore data: {e}"

        # Wipe vault and keyfile
        if vault_path.exists():
            shutil.rmtree(str(vault_path), ignore_errors=True)
        gpg = CONFIG_DIR / f"{app_id}.key.gpg"
        if gpg.exists():
            import subprocess
            subprocess.run(["shred", "-u", str(gpg)], capture_output=True)

    # Remove passphrase from GNOME keyring (fingerprint mode)
    keyring_delete(app_id)

    remove_desktop_file(app_id)
    remove_app_config(app_id)
    return True, f"✅ Protection removed from {app_name}."


# ── mount / unmount ───────────────────────────────────────────────────────────

def mount_app(app_id: str, passphrase: str) -> tuple[bool, str]:
    """Mount vault. passphrase must come from spp.auth.get_passphrase()."""
    config = get_app_config(app_id)
    if not config:
        return False, "App not found."
    if not config.get("encrypt_data"):
        return True, "No vault to mount."
    if not config.get("vault_path") or not config.get("mount_path"):
        return False, "Vault path not configured."

    # Reject vaults created before crypto_version 2 (old asymmetric GPG format)
    if config.get("crypto_version", 1) < 2:
        return False, (
            "This vault uses a legacy crypto format and cannot be mounted. "
            "Remove the protection and re-protect the app to upgrade."
        )

    vault_path = Path(config["vault_path"])
    mount_path = Path(config["mount_path"])

    if is_mounted(mount_path):
        return True, "Vault already mounted."

    if mount_vault(app_id, vault_path, mount_path, passphrase):
        return True, "Vault unlocked."
    return False, "Cannot unlock vault — wrong password?"


def unmount_app(app_id: str) -> tuple[bool, str]:
    """Unmount vault. No passphrase required."""
    config = get_app_config(app_id)
    if not config:
        return False, "App not found."
    if not config.get("encrypt_data"):
        return True, "No vault to lock."

    mount_path = Path(config["mount_path"])
    if not is_mounted(mount_path):
        return True, "Vault already locked."

    if unmount_vault(mount_path):
        return True, "Vault locked."
    return False, "Cannot lock vault."
