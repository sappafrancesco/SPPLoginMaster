# SPPLoginMaster

Fingerprint and password-based app protection for Linux.  
Wraps any application with authentication and optional data encryption via gocryptfs + GPG.

Supports snap, flatpak, and .deb applications on Ubuntu 22.04+.

---

## Features

- Fingerprint authentication via `fprintd`
- Password authentication via PAM
- Double factor (fingerprint + password)
- Per-app data encryption with `gocryptfs` + GPG (RSA 4096)
- App discovery across snap, flatpak, and .deb
- GTK4/Libadwaita GUI
- CLI with interactive wizard
- Panic mode: unmount all vaults instantly
- Per-app configuration with independent auth methods

---

## Requirements

| Package | Purpose |
|---------|---------|
| `fprintd` | Fingerprint daemon |
| `gocryptfs` | Filesystem encryption |
| `gnupg2` | GPG key management |
| `fuse` | FUSE mounting |
| `zenity` | Wrapper dialogs |
| `python3-gi` | GTK4 bindings |
| `libadwaita-1` | GNOME UI library |

---

## Installation

```bash
git clone https://github.com/sappafrancesco/SPPLoginMaster.git
cd SPPLoginMaster
chmod +x install.sh
./install.sh
```

---

## Usage

### GUI

```bash
spp-gui
```

### CLI

```bash
# First-time setup
spp-cli setup

# Protect an app (interactive)
spp-cli protect

# Protect a specific app
spp-cli protect --app-id snap:proton-mail --auth fingerprint

# List protected apps
spp-cli list

# Mount vault manually
spp-cli mount snap:proton-mail

# Unmount vault
spp-cli unmount snap:proton-mail

# Remove protection
spp-cli unprotect snap:proton-mail

# Unmount all vaults immediately
spp-cli panic

# Status overview
spp-cli status
```

---

## How it works

1. On setup, a GPG key pair (RSA 4096) is generated in `~/.gnupg`
2. For each protected app, a random 32-byte key is generated and encrypted with GPG into `~/.config/spploginmaster/<app>.key.gpg`
3. A `gocryptfs` vault is initialized using the GPG keyfile as passphrase
4. Existing app data is migrated into the vault
5. A bash wrapper is created that:
   - Verifies the user (fingerprint / password / both)
   - Decrypts the GPG keyfile in memory
   - Mounts the vault at the original data path
   - Launches the app
   - Unmounts on exit
6. The app's `.desktop` launcher is patched to use the wrapper

---

## Security model

| Threat | Status |
|--------|--------|
| Unauthorized app launch | blocked by wrapper |
| Physical disk access | encrypted by gocryptfs |
| Direct `snap run` bypass | vault unmounted, app sees empty data |
| Root access | not protected by design |

Protection is user-level. It is not a substitute for full-disk encryption (LUKS) or TPM-based solutions.

---

## Configuration

Stored in `~/.config/spploginmaster/apps.json`:

```json
{
  "snap:proton-mail": {
    "id": "snap:proton-mail",
    "name": "proton-mail",
    "type": "snap",
    "auth_method": "fingerprint",
    "encrypt_data": true,
    "vault_path": "~/.local/share/spploginmaster/vaults/snap_proton-mail",
    "mount_path": "~/snap/proton-mail",
    "launch_cmd": "snap run proton-mail"
  }
}
```

---

## Project structure

```
SPPLoginMaster/
├── spp/
│   ├── cli.py        # CLI (Click + Rich)
│   ├── gui.py        # GTK4/Libadwaita GUI
│   ├── protect.py    # protect/unprotect workflow
│   ├── security.py   # fingerprint, GPG, gocryptfs
│   ├── apps.py       # app discovery
│   ├── launcher.py   # .desktop management
│   └── config.py     # JSON config
├── install.sh
├── setup.py
└── README.md
```

---

## Contributing

Open an issue before submitting a pull request.

## License

GPL-3.0 — see [LICENSE](LICENSE)
