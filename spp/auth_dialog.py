"""
SPPLoginMaster - Graphical Authentication Dialog

Standalone GTK4/libadwaita window launched by `spp-cli auth-mount`.
Provides live fingerprint feedback, animated states, and auto-retry.
"""

import os
import threading

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk, Gio   # noqa: E402

from spp.config import get_app_config

# ── CSS ───────────────────────────────────────────────────────────────────────

_CSS = """
@keyframes fp-pulse {
  0%, 100% { opacity: 1.0;  }
  50%       { opacity: 0.2;  }
}
@keyframes fp-shake {
  0%,100% { margin-left: 0;    }
  20%     { margin-left: -10px;}
  40%     { margin-left:  10px;}
  60%     { margin-left: -6px; }
  80%     { margin-left:  6px; }
}

.fp-idle     { opacity: 0.35; }
.fp-scanning { animation: fp-pulse 1.4s ease-in-out infinite; }
.fp-error    { animation: fp-shake 0.45s ease-in-out;
               color: @error_color; }
.fp-success  { color: @success_color; }

.status-scanning { color: @accent_color; }
.status-error    { color: @error_color;   }
.status-success  { color: @success_color; font-weight: bold; }

.attempts-label { color: alpha(@error_color, 0.85); }

.auth-title    { font-size: 22px; font-weight: bold; }
.auth-subtitle { font-size: 13px; }
"""


# ── Helper ────────────────────────────────────────────────────────────────────

def _app_icon_widget(desktop_file: str, size: int) -> Gtk.Image:
    img = Gtk.Image()
    img.set_pixel_size(size)
    icon_name = None
    if desktop_file:
        try:
            from pathlib import Path
            for line in Path(desktop_file).read_text(errors="replace").splitlines():
                if line.startswith("Icon="):
                    icon_name = line[5:].strip()
                    break
        except Exception:
            pass
    img.set_from_icon_name(icon_name or "application-x-executable-symbolic")
    return img


# ── Main window ───────────────────────────────────────────────────────────────

class AuthWindow(Adw.ApplicationWindow):
    """
    State machine:
      "idle"     – initial, fingerprint icon dimmed
      "scanning" – pulsing animation, waiting for scan
      "success"  – green icon, closing soon
      "error"    – red shake, retry countdown
    For password/both modes an input card is shown; the fingerprint area
    transitions to scanning AFTER the user clicks the action button.
    """

    def __init__(self, application: Adw.Application, app_id: str, result: list):
        super().__init__(application=application)
        self.set_default_size(380, 500)
        self.set_resizable(False)

        self._app_id   = app_id
        self._result   = result
        self._attempts = 0
        self._closing  = False

        cfg = get_app_config(app_id) or {}
        self._method   = cfg.get("auth_method", "fingerprint")
        self._app_name = cfg.get("name", app_id)
        self._desktop  = cfg.get("desktop_file", "")

        # Inject CSS
        prov = Gtk.CssProvider()
        prov.load_from_string(_CSS)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), prov,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

        self._build_ui()
        self.connect("close-request", self._on_close_request)

        # Kick off authentication
        GLib.idle_add(self._start)

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        toolbar_view = Adw.ToolbarView()
        self.set_content(toolbar_view)

        hb = Adw.HeaderBar()
        hb.add_css_class("flat")
        hb.set_show_title(False)
        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", self._cancel)
        hb.pack_start(cancel_btn)
        toolbar_view.add_top_bar(hb)

        # Scrollable body
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        toolbar_view.set_content(scroll)

        clamp = Adw.Clamp(maximum_size=340, margin_top=8, margin_bottom=32,
                          margin_start=20, margin_end=20)
        scroll.set_child(clamp)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0,
                       valign=Gtk.Align.CENTER, vexpand=True)
        clamp.set_child(root)

        # App icon + name
        icon_w = _app_icon_widget(self._desktop, 72)
        icon_w.set_margin_bottom(14)
        root.append(icon_w)

        name_lbl = Gtk.Label(label=self._app_name)
        name_lbl.add_css_class("auth-title")
        name_lbl.set_margin_bottom(6)
        root.append(name_lbl)

        sub = Gtk.Label(label="Authentication required to unlock")
        sub.add_css_class("dim-label")
        sub.add_css_class("auth-subtitle")
        sub.set_margin_bottom(36)
        root.append(sub)

        # ── Fingerprint area ──────────────────────────────────────────────────
        if self._method in ("fingerprint", "both"):
            fp_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10,
                             halign=Gtk.Align.CENTER, margin_bottom=28)

            self._fp_icon = Gtk.Image.new_from_icon_name("fingerprint-symbolic")
            self._fp_icon.set_pixel_size(96)
            self._fp_icon.add_css_class("fp-idle")
            fp_box.append(self._fp_icon)

            self._fp_status = Gtk.Label(label="")
            self._fp_status.add_css_class("body")
            self._fp_status.set_justify(Gtk.Justification.CENTER)
            self._fp_status.set_wrap(True)
            fp_box.append(self._fp_status)

            root.append(fp_box)

        # ── Password area ─────────────────────────────────────────────────────
        if self._method in ("password", "both"):
            pw_group = Adw.PreferencesGroup(margin_bottom=16)
            self._pw_entry = Adw.PasswordEntryRow(title="Password")
            self._pw_entry.connect("entry-activated", self._on_submit)
            pw_group.add(self._pw_entry)
            root.append(pw_group)

            if self._method == "both":
                # Start disabled: fingerprint must succeed first
                self._pw_entry.set_sensitive(False)

        # ── Action button ─────────────────────────────────────────────────────
        if self._method in ("password", "both"):
            btn_label = {
                "password": "Unlock",
                "both":     "Scan & Unlock",
            }[self._method]
            self._action_btn = Gtk.Button(
                label=btn_label,
                halign=Gtk.Align.CENTER,
                css_classes=["suggested-action", "pill"],
            )
            self._action_btn.set_size_request(180, -1)
            self._action_btn.connect("clicked", self._on_submit)
            if self._method == "both":
                self._action_btn.set_sensitive(False)
            root.append(self._action_btn)

        # ── Attempts label ────────────────────────────────────────────────────
        self._attempts_lbl = Gtk.Label(label="")
        self._attempts_lbl.add_css_class("attempts-label")
        self._attempts_lbl.add_css_class("caption")
        self._attempts_lbl.set_halign(Gtk.Align.CENTER)
        self._attempts_lbl.set_margin_top(14)
        root.append(self._attempts_lbl)

    # ── State helpers ─────────────────────────────────────────────────────────

    def _fp_set(self, state: str, text: str = ""):
        """Update fingerprint icon CSS class and status label."""
        for cls in ("fp-idle", "fp-scanning", "fp-error", "fp-success"):
            self._fp_icon.remove_css_class(cls)
        for cls in ("status-scanning", "status-error", "status-success"):
            self._fp_status.remove_css_class(cls)

        icon_map = {
            "idle":     ("fingerprint-symbolic",  "fp-idle"),
            "scanning": ("fingerprint-symbolic",  "fp-scanning"),
            "error":    ("fingerprint-symbolic",  "fp-error"),
            "success":  ("emblem-ok-symbolic",    "fp-success"),
        }
        icon_name, css = icon_map.get(state, ("fingerprint-symbolic", "fp-idle"))
        self._fp_icon.set_from_icon_name(icon_name)
        self._fp_icon.add_css_class(css)
        self._fp_status.add_css_class(f"status-{state}" if state != "idle" else "dim-label")
        self._fp_status.set_label(text)

    def _bump_attempts(self):
        self._attempts += 1
        n = self._attempts
        word = "attempt" if n == 1 else "attempts"
        self._attempts_lbl.set_label(f"{n} failed {word}")

    # ── Auth flow ─────────────────────────────────────────────────────────────

    def _start(self):
        if self._method == "fingerprint":
            self._scan_fingerprint()
        elif self._method == "password":
            self._pw_entry.grab_focus()
        elif self._method == "both":
            # Scan fingerprint while user optionally types password
            self._scan_fingerprint_for_both()

    # fingerprint-only ─────────────────────────────────────────────────────────

    def _scan_fingerprint(self):
        if self._closing:
            return
        self._fp_set("scanning", "Place your finger on the sensor…")

        def work():
            from spp.auth import get_passphrase

            def on_status(msg):
                GLib.idle_add(self._fp_set, "error", msg)

            pp = get_passphrase(self._app_id, status_cb=on_status)
            GLib.idle_add(self._on_fp_only_result, pp)

        threading.Thread(target=work, daemon=True).start()

    def _on_fp_only_result(self, passphrase):
        if self._closing:
            return
        if passphrase:
            self._fp_set("success", "Fingerprint recognised!")
            self._result[0] = passphrase
            GLib.timeout_add(650, self._finish)
        else:
            self._bump_attempts()
            self._fp_set("error", "Not recognised — try again…")
            GLib.timeout_add(1800, self._scan_fingerprint)

    # fingerprint step for "both" mode ────────────────────────────────────────

    def _scan_fingerprint_for_both(self):
        if self._closing:
            return
        self._fp_set("scanning", "Place your finger on the sensor…")

        def work():
            from spp.security import verify_fingerprint
            cfg = get_app_config(self._app_id) or {}
            username = cfg.get("username", os.environ.get("USER", ""))

            def on_status(msg):
                GLib.idle_add(self._fp_set, "error", msg)

            ok = verify_fingerprint(username, status_cb=on_status)
            GLib.idle_add(self._on_fp_for_both, ok)

        threading.Thread(target=work, daemon=True).start()

    def _on_fp_for_both(self, ok: bool):
        if self._closing:
            return
        if ok:
            self._fp_set("success", "Fingerprint OK — enter your password")
            self._pw_entry.set_sensitive(True)
            self._action_btn.set_sensitive(True)
            self._pw_entry.grab_focus()
        else:
            self._bump_attempts()
            self._fp_set("error", "Not recognised — try again…")
            GLib.timeout_add(1500, self._scan_fingerprint_for_both)

    # password / both submit ───────────────────────────────────────────────────

    def _on_submit(self, _):
        password = self._pw_entry.get_text() if self._method in ("password", "both") else None
        if self._method in ("password", "both") and not password:
            self._pw_entry.add_css_class("error")
            GLib.timeout_add(700, lambda: self._pw_entry.remove_css_class("error") or False)
            return

        self._action_btn.set_sensitive(False)
        self._pw_entry.set_sensitive(False)

        if self._method in ("fingerprint", "both"):
            self._fp_set("scanning", "Verifying…")

        def work():
            from spp.auth import get_passphrase
            pp = get_passphrase(self._app_id, password=password)
            GLib.idle_add(self._on_submit_result, pp)

        threading.Thread(target=work, daemon=True).start()

    def _on_submit_result(self, passphrase):
        if self._closing:
            return
        if passphrase:
            if self._method in ("fingerprint", "both"):
                self._fp_set("success", "Authenticated!")
            self._result[0] = passphrase
            GLib.timeout_add(600, self._finish)
        else:
            self._bump_attempts()
            if self._method in ("fingerprint", "both"):
                self._fp_set("error", "Wrong password or fingerprint mismatch")
            self._pw_entry.set_text("")
            self._pw_entry.add_css_class("error")
            self._pw_entry.set_sensitive(True)
            self._action_btn.set_sensitive(True)
            self._pw_entry.grab_focus()
            GLib.timeout_add(800, lambda: self._pw_entry.remove_css_class("error") or False)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def _finish(self):
        self._closing = True
        self.get_application().quit()

    def _cancel(self, _=None):
        self._closing = True
        self._result[0] = None
        self.get_application().quit()

    def _on_close_request(self, _):
        if not self._closing:
            self._cancel()
        return False


# ── Application ───────────────────────────────────────────────────────────────

class SPPAuthApp(Adw.Application):
    def __init__(self, app_id: str, result: list):
        super().__init__(
            application_id="com.francescosappa.spploginmaster.auth",
            flags=Gio.ApplicationFlags.NON_UNIQUE,
        )
        self._app_id = app_id
        self._result = result
        self.connect("activate", self._on_activate)

    def _on_activate(self, _):
        win = AuthWindow(self, self._app_id, self._result)
        win.present()


# ── Public entry point ────────────────────────────────────────────────────────

def run_auth_dialog(app_id: str) -> str | None:
    """
    Show the graphical auth dialog and return the passphrase on success,
    or None if the user cancelled / authentication failed definitively.
    """
    result = [None]
    SPPAuthApp(app_id, result).run([])
    return result[0]
