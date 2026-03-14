# 🔒 SPPLoginMaster

**Secure Privacy Protection Login Master**

Protect any Linux app with fingerprint authentication and data encryption.  
Works with Snap, Flatpak, and .deb applications on Ubuntu/Debian.

---

## ✨ Features

- 🖐 **Fingerprint authentication** via `fprintd`
- 🔑 **Password authentication** via PAM
- 🖐+🔑 **Both** (double factor)
- 🔐 **Data encryption** with `gocryptfs` + GPG key
- 📦 **Supports Snap, Flatpak, .deb** apps
- 🖥 **GTK4/Libadwaita GUI** (native GNOME look)
- 💻 **Full CLI** with interactive wizard
- 🚨 **Panic mode**: unmount all vaults instantly
- 🔄 **Per-app configuration**: different auth per app

---

## 🔧 Requirements

| Dependency | Purpose |
|------------|---------|
| `fprintd` | Fingerprint authentication |
| `gocryptfs` | Data encryption |
| `gnupg2` | GPG key management |
| `fuse` | Filesystem mounting |
| `zenity` | GUI dialogs in wrappers |
| `python3-gi` | GTK4 Python bindings |
| `libadwaita` | GNOME UI library |

---

## 📥 Installation

```bash
git clone https://github.com/youruser/SPPLoginMaster.git
cd SPPLoginMaster
chmod +x install.sh
./install.sh
```

---

## 🚀 Usage

### GUI

```bash
spp-gui
```

### CLI

```bash
# Initial setup (run once)
spp-cli setup

# Protect an app (interactive wizard)
spp-cli protect

# Protect a specific app directly
spp-cli protect --app-id snap:proton-mail --auth fingerprint

# List protected apps
spp-cli list

# Mount a vault manually
spp-cli mount snap:proton-mail

# Unmount a vault
spp-cli unmount snap:proton-mail

# Remove protection
spp-cli unprotect snap:proton-mail

# Emergency: unmount everything
spp-cli panic

# Status overview
spp-cli status
```

---

## 🏗 Architecture

```
SPPLoginMaster/
├── spp/
│   ├── cli.py        # CLI (Click + Rich)
│   ├── gui.py        # GTK4/Libadwaita GUI
│   ├── protect.py    # Protect/unprotect workflow
│   ├── security.py   # Fingerprint, GPG, gocryptfs
│   ├── apps.py       # App discovery (snap/flatpak/deb)
│   ├── launcher.py   # .desktop file management
│   └── config.py     # JSON config manager
├── install.sh
├── setup.py
└── README.md
```

---

## 🔐 How It Works

1. **Setup**: generates a GPG key pair (RSA 4096) stored in `~/.gnupg`
2. **Per-app keyfile**: generates a random 32-byte key, encrypts it with GPG → `~/.config/spploginmaster/<app>.key.gpg`
3. **Vault init**: initializes a `gocryptfs` vault using the GPG keyfile as password
4. **Data migration**: moves existing app data into the encrypted vault
5. **Wrapper script**: creates a bash wrapper that:
   - Verifies fingerprint/password
   - Decrypts GPG keyfile in memory
   - Mounts the vault at the original data path
   - Launches the app
   - Unmounts on exit
6. **Desktop integration**: patches the `.desktop` launcher to use the wrapper

---

## 🛡 Security Model

| Threat | Protection |
|--------|-----------|
| Someone opens the app without auth | Wrapper blocks launch |
| Physical access to disk | gocryptfs encryption |
| Bypass via `snap run` directly | Vault unmounted = app sees empty data |
| Root access | Not protected (by design — root can do anything) |

> **Note**: Protection is user-level. Root access can always bypass it. For full disk encryption, use LUKS.

---

## ⚙ Configuration

Config is stored in `~/.config/spploginmaster/apps.json`:

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

## 🤝 Contributing

Pull requests welcome. Please open an issue first to discuss changes.

---

## 📄 License

GPL-3.0 — see [LICENSE](LICENSE)

---

## ⚠️ Disclaimer

This tool provides **user-level** security. It is not a substitute for full-disk encryption (LUKS) or hardware security modules (TPM). Use responsibly.
