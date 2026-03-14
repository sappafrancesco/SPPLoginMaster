"""
SPPLoginMaster - GTK4 / Adwaita GUI  (requires libadwaita ≥ 1.4)
"""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib, Gio, GdkPixbuf, Gdk

import os
import subprocess
import threading
from pathlib import Path

from spp.apps import get_all_apps
from spp.config import list_apps, get_app_config
from spp.auth import get_passphrase
from spp.protect import protect_app, unprotect_app, mount_app, unmount_app
from spp.security import (
    check_dependencies, install_dependencies,
    is_fingerprint_available,
    is_mounted, unmount_all,
)

VERSION = "2.0.0"

CSS = b"""
.stat-card {
    border-radius: 12px;
    padding: 4px 8px;
}
.mounted-badge {
    border-radius: 99px;
    padding: 2px 10px;
    font-size: 0.75rem;
    font-weight: 700;
    background-color: alpha(@success_color, 0.15);
    color: @success_color;
}
.unmounted-badge {
    border-radius: 99px;
    padding: 2px 10px;
    font-size: 0.75rem;
    font-weight: 700;
    background-color: alpha(@error_color, 0.15);
    color: @error_color;
}
.auth-badge {
    border-radius: 99px;
    padding: 2px 10px;
    font-size: 0.75rem;
    font-weight: 600;
    background-color: alpha(@accent_bg_color, 0.15);
    color: @accent_color;
}
.enc-badge {
    border-radius: 99px;
    padding: 2px 10px;
    font-size: 0.75rem;
    font-weight: 600;
    background-color: alpha(@accent_bg_color, 0.10);
    color: @accent_color;
}
.step-circle {
    border-radius: 99px;
    min-width: 26px;
    min-height: 26px;
    font-weight: 700;
    font-size: 0.85rem;
}
.step-active {
    background-color: @accent_bg_color;
    color: @accent_fg_color;
}
.step-done {
    background-color: @success_color;
    color: white;
}
.step-inactive {
    background-color: alpha(currentColor, 0.12);
    color: alpha(currentColor, 0.4);
}
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _vault_size(vault_path: str) -> str:
    try:
        r = subprocess.run(["du", "-sh", vault_path], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return r.stdout.split()[0]
    except Exception:
        pass
    return "?"


def _load_icon(app_config: dict, size: int = 40) -> Gtk.Widget:
    """Return an icon widget for the app (pixbuf → theme → Avatar fallback)."""
    icon_path = app_config.get("icon")
    if icon_path and Path(icon_path).exists():
        try:
            pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(icon_path, size, size, True)
            img = Gtk.Image.new_from_pixbuf(pb)
            img.set_pixel_size(size)
            return img
        except Exception:
            pass

    desktop = app_config.get("desktop_file")
    if desktop and Path(desktop).exists():
        try:
            with open(desktop) as f:
                for line in f:
                    if line.startswith("Icon="):
                        name = line.split("=", 1)[1].strip()
                        theme = Gtk.IconTheme.get_for_display(Gdk.Display.get_default())
                        if theme.has_icon(name):
                            img = Gtk.Image.new_from_icon_name(name)
                            img.set_pixel_size(size)
                            return img
        except Exception:
            pass

    return Adw.Avatar(size=size, text=app_config.get("name", "?"), show_initials=True)


def _badge(text: str, css: str) -> Gtk.Label:
    lbl = Gtk.Label(label=text)
    lbl.add_css_class(css)
    lbl.set_valign(Gtk.Align.CENTER)
    return lbl


# ── Application ───────────────────────────────────────────────────────────────

class SPPApp(Adw.Application):
    def __init__(self):
        super().__init__(
            application_id="com.spploginmaster.app",
            flags=Gio.ApplicationFlags.FLAGS_NONE,
        )
        self.connect("activate", self._on_activate)

    def _on_activate(self, _):
        provider = Gtk.CssProvider()
        provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

        self.win = SPPMainWindow(application=self)

        # Application-wide actions
        for name, cb, accel in [
            ("quit",    lambda *_: self.quit(),               "<Primary>q"),
            ("about",   self._on_about,                       None),
            ("panic",   lambda *_: self.win.on_panic_request(), "<Primary><Shift>l"),
            ("setup",   lambda *_: SetupDialog(self.win).present(), None),
            ("refresh", lambda *_: self.win.refresh(),        "<Primary>r"),
        ]:
            a = Gio.SimpleAction.new(name, None)
            a.connect("activate", cb)
            self.add_action(a)
            if accel:
                self.set_accels_for_action(f"app.{name}", [accel])

        self.win.present()

    def _on_about(self, *_):
        Adw.AboutDialog(
            application_name="SPPLoginMaster",
            application_icon="security-high-symbolic",
            developer_name="Francesco Sappa",
            version=VERSION,
            comments=(
                "Protect your Linux apps with fingerprint or password.\n"
                "App data is encrypted with gocryptfs, secured by a GPG key."
            ),
            license_type=Gtk.License.GPL_3_0,
        ).present(self.win)


# ── Main Window ───────────────────────────────────────────────────────────────

class SPPMainWindow(Adw.ApplicationWindow):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.set_title("SPPLoginMaster")
        self.set_default_size(840, 640)
        self._refresh_id = None

        # Root: toast overlay
        self.toasts = Adw.ToastOverlay()
        self.set_content(self.toasts)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.toasts.set_child(root)

        # ── Header ────────────────────────────────────────────────────
        hb = Adw.HeaderBar()
        hb.set_centering_policy(Adw.CenteringPolicy.STRICT)
        hb.set_title_widget(Adw.WindowTitle(title="SPPLoginMaster", subtitle="App Protection"))

        add_btn = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="Protect new app  (Ctrl+N)")
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", lambda _: ProtectWizard(self).present())
        hb.pack_start(add_btn)
        self.get_application().set_accels_for_action("win.add-app", ["<Primary>n"])

        self.search_btn = Gtk.ToggleButton(icon_name="system-search-symbolic", tooltip_text="Search  (Ctrl+F)")
        self.search_btn.connect("toggled", self._on_search_toggle)
        hb.pack_end(self.search_btn)
        self.get_application().set_accels_for_action("win.search", ["<Primary>f"])

        panic_btn = Gtk.Button(icon_name="changes-prevent-symbolic", tooltip_text="Lock all vaults  (Ctrl+Shift+L)")
        panic_btn.add_css_class("destructive-action")
        panic_btn.connect("clicked", lambda _: self.on_panic_request())
        hb.pack_end(panic_btn)

        menu = Gio.Menu()
        menu.append("Setup", "app.setup")
        menu.append("Refresh", "app.refresh")
        menu.append("About", "app.about")
        menu.append("Quit", "app.quit")
        hb.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu))

        root.append(hb)

        # ── Search bar ────────────────────────────────────────────────
        self.search_bar = Gtk.SearchBar()
        self.search_entry = Gtk.SearchEntry(placeholder_text="Search protected apps…", hexpand=True)
        self.search_entry.connect("search-changed", self._on_search)
        self.search_bar.set_child(self.search_entry)
        self.search_bar.connect_entry(self.search_entry)
        root.append(self.search_bar)

        # ── Scrollable body ───────────────────────────────────────────
        scroll = Gtk.ScrolledWindow(vexpand=True)
        clamp = Adw.Clamp(maximum_size=780, tightening_threshold=600,
                          margin_top=20, margin_bottom=20,
                          margin_start=16, margin_end=16)
        scroll.set_child(clamp)
        root.append(scroll)

        self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(self.body)

        self.refresh()
        self._refresh_id = GLib.timeout_add_seconds(30, self._tick)

    # ── Public ────────────────────────────────────────────────────────

    def toast(self, msg: str, timeout: int = 3):
        self.toasts.add_toast(Adw.Toast(title=msg, timeout=timeout))

    def refresh(self):
        while c := self.body.get_first_child():
            self.body.remove(c)
        self._rows = []
        self._build_body()

    # ── Body builder ──────────────────────────────────────────────────

    def _build_body(self):
        apps = list_apps()
        mounted_n = sum(
            1 for a in apps
            if a.get("mount_path") and is_mounted(Path(a["mount_path"]))
        )

        # Stats row
        stats = Gtk.Box(spacing=12, homogeneous=True)
        for title, subtitle, icon in [
            (str(len(apps)),             "Protected",  "security-high-symbolic"),
            (str(mounted_n),             "Unlocked",   "changes-allow-symbolic"),
            (str(len(apps) - mounted_n), "Locked",     "changes-prevent-symbolic"),
        ]:
            row = Adw.ActionRow(title=title, subtitle=subtitle)
            row.set_icon_name(icon)
            row.add_css_class("card")
            row.add_css_class("stat-card")
            stats.append(row)
        self.body.append(stats)

        # Missing dependencies banner
        missing = check_dependencies()
        if missing:
            banner = Adw.Banner(
                title=f"Missing: {', '.join(missing)}",
                button_label="Open Setup",
                revealed=True,
            )
            banner.connect("button-clicked", lambda _: SetupDialog(self).present())
            self.body.append(banner)

        # Empty state
        if not apps:
            sp = Adw.StatusPage(
                title="No protected apps yet",
                description='Click "Protect App" to secure your first application with fingerprint or password.',
                icon_name="security-high-symbolic",
            )
            btn = Gtk.Button(label="Protect your first app", halign=Gtk.Align.CENTER)
            btn.add_css_class("suggested-action")
            btn.add_css_class("pill")
            btn.connect("clicked", lambda _: ProtectWizard(self).present())
            sp.set_child(btn)
            self.body.append(sp)
            return

        lbl = Gtk.Label(label="Protected Applications", halign=Gtk.Align.START)
        lbl.add_css_class("heading")
        self.body.append(lbl)

        lb = Gtk.ListBox()
        lb.add_css_class("boxed-list")
        lb.set_selection_mode(Gtk.SelectionMode.NONE)
        self.body.append(lb)

        for app in apps:
            row = self._build_row(app)
            lb.append(row)
            self._rows.append((row, app.get("name", app["id"])))

    def _build_row(self, app: dict) -> Adw.ExpanderRow:
        app_id   = app["id"]
        name     = app.get("name", app_id)
        auth     = app.get("auth_method", "fingerprint")
        enc      = app.get("encrypt_data", False)
        mp       = app.get("mount_path")
        vp       = app.get("vault_path")
        mounted  = is_mounted(Path(mp)) if mp else False

        row = Adw.ExpanderRow(title=name)
        row.set_subtitle(app.get("type", "").upper())

        # Icon prefix
        icon = _load_icon(app, 40)
        icon.set_valign(Gtk.Align.CENTER)
        row.add_prefix(icon)

        # Badges
        bx = Gtk.Box(spacing=6, valign=Gtk.Align.CENTER)
        bx.append(_badge("Unlocked" if mounted else "Locked",
                         "mounted-badge" if mounted else "unmounted-badge"))
        auth_text = {"fingerprint": "🖐 Fingerprint", "password": "🔑 Password",
                     "both": "🖐+🔑 Both"}.get(auth, auth)
        bx.append(_badge(auth_text, "auth-badge"))
        if enc:
            bx.append(_badge("🔐 Encrypted", "enc-badge"))
        row.add_suffix(bx)

        # ── Expanded: details ─────────────────────────────────────────
        if mp:
            pr = Adw.ActionRow(title="Data path", subtitle=mp, icon_name="folder-symbolic")
            pr.set_subtitle_selectable(True)
            ob = Gtk.Button(icon_name="document-open-symbolic", valign=Gtk.Align.CENTER,
                            tooltip_text="Open in Files")
            ob.add_css_class("flat")
            ob.connect("clicked", lambda _, p=mp: subprocess.Popen(["xdg-open", p]))
            pr.add_suffix(ob)
            row.add_row(pr)

        if vp and enc:
            size = _vault_size(vp)
            vr = Adw.ActionRow(
                title="Vault",
                subtitle=f"{size}  ·  {vp}",
                icon_name="drive-harddisk-symbolic",
            )
            vr.set_subtitle_selectable(True)
            row.add_row(vr)

        tr = Adw.ActionRow(
            title="Identifier",
            subtitle=app_id,
            icon_name="application-x-executable-symbolic",
        )
        tr.set_subtitle_selectable(True)
        row.add_row(tr)

        # ── Expanded: actions ─────────────────────────────────────────
        ar = Adw.ActionRow(title="Actions")
        ab = Gtk.Box(spacing=8, valign=Gtk.Align.CENTER)

        if enc:
            if mounted:
                b = Gtk.Button(label="Lock")
                b.add_css_class("pill")
                b.connect("clicked", self._on_unmount, app_id)
            else:
                b = Gtk.Button(label="Unlock")
                b.add_css_class("suggested-action")
                b.add_css_class("pill")
                b.connect("clicked", self._on_mount, app_id)
            ab.append(b)

        rb = Gtk.Button(label="Remove Protection")
        rb.add_css_class("destructive-action")
        rb.add_css_class("pill")
        rb.connect("clicked", self._on_unprotect_confirm, app_id, name)
        ab.append(rb)

        ar.add_suffix(ab)
        row.add_row(ar)
        return row

    # ── Operations ────────────────────────────────────────────────────

    def _on_mount(self, btn, app_id):
        btn.set_sensitive(False)
        def on_auth(passphrase):
            def run():
                ok, msg = mount_app(app_id, passphrase)
                GLib.idle_add(self._done, ok, msg)
            threading.Thread(target=run, daemon=True).start()
        def on_cancel():
            btn.set_sensitive(True)
        AuthDialog(app_id, on_success=on_auth, on_cancel=on_cancel).present(self)

    def _on_unmount(self, btn, app_id):
        btn.set_sensitive(False)
        def run():
            ok, msg = unmount_app(app_id)
            GLib.idle_add(self._done, ok, msg)
        threading.Thread(target=run, daemon=True).start()

    def _on_unprotect_confirm(self, _btn, app_id, name):
        d = Adw.AlertDialog(
            heading="Remove protection?",
            body=f"Data will be decrypted and restored for <b>{name}</b>.\nAuthentication is required.",
            body_use_markup=True,
        )
        d.add_response("cancel", "Cancel")
        d.add_response("remove", "Remove Protection")
        d.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        d.connect("response", self._on_unprotect_auth, app_id)
        d.present(self)

    def _on_unprotect_auth(self, _dlg, response, app_id):
        if response != "remove":
            return
        cfg = get_app_config(app_id)
        needs_auth = cfg and cfg.get("encrypt_data")
        if needs_auth:
            def on_auth(passphrase):
                self._run_unprotect(app_id, passphrase)
            AuthDialog(app_id, on_success=on_auth).present(self)
        else:
            self._run_unprotect(app_id, None)

    def _run_unprotect(self, app_id: str, passphrase):
        def run():
            try:
                ok, msg = unprotect_app(app_id, passphrase)
            except Exception as e:
                ok, msg = False, f"Error: {e}"
            GLib.idle_add(self._done, ok, msg)
        threading.Thread(target=run, daemon=True).start()

    def on_panic_request(self):
        d = Adw.AlertDialog(
            heading="Lock all vaults?",
            body="All unlocked vaults will be immediately locked. Running apps may lose access to their data.",
        )
        d.add_response("cancel", "Cancel")
        d.add_response("lock", "Lock All Now")
        d.set_response_appearance("lock", Adw.ResponseAppearance.DESTRUCTIVE)
        d.connect("response", self._on_panic_confirmed)
        d.present(self)

    def _on_panic_confirmed(self, _dlg, response):
        if response == "lock":
            results = unmount_all()
            n = sum(1 for _, ok in results if ok)
            self._done(True, f"🔒 {n} vault(s) locked.")

    def _done(self, ok: bool, msg: str):
        self.toast(msg, timeout=4 if not ok else 3)
        self.refresh()

    # ── Search ────────────────────────────────────────────────────────

    def _on_search_toggle(self, btn):
        self.search_bar.set_search_mode(btn.get_active())
        if btn.get_active():
            self.search_entry.grab_focus()

    def _on_search(self, entry):
        q = entry.get_text().lower()
        for row, name in self._rows:
            row.set_visible(not q or q in name.lower())

    def _tick(self):
        self.refresh()
        return GLib.SOURCE_CONTINUE

    def do_close_request(self):
        if self._refresh_id:
            GLib.source_remove(self._refresh_id)
        return False


# ── Auth Dialog ───────────────────────────────────────────────────────────────

class AuthDialog(Adw.Dialog):
    """
    Collects credentials for the app's configured auth method, then calls
    on_success(passphrase) on the GTK main thread.
    The passphrase is derived / retrieved inside a background thread —
    the GUI never handles raw crypto material directly.
    """

    def __init__(self, app_id: str, on_success, on_cancel=None):
        super().__init__(title="Authenticate")
        self.set_content_width(380)
        self.set_content_height(320)
        self._app_id     = app_id
        self._on_success = on_success
        self._on_cancel  = on_cancel

        cfg = get_app_config(app_id)
        self._method   = cfg.get("auth_method", "fingerprint") if cfg else "fingerprint"
        self._app_name = cfg.get("name", app_id) if cfg else app_id

        # ── Layout ────────────────────────────────────────────────────
        self.toasts = Adw.ToastOverlay()
        self.set_child(self.toasts)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.toasts.set_child(outer)

        hb = Adw.HeaderBar()
        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", self._cancel)
        hb.pack_start(cancel_btn)
        outer.append(hb)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16,
                       margin_top=24, margin_bottom=24,
                       margin_start=20, margin_end=20,
                       valign=Gtk.Align.CENTER, vexpand=True)

        icon_name = ("fingerprint-symbolic"
                     if "fingerprint" in self._method
                     else "dialog-password-symbolic")
        ico = Gtk.Image.new_from_icon_name(icon_name)
        ico.set_pixel_size(56)
        ico.add_css_class("dim-label")
        body.append(ico)

        body.append(Gtk.Label(
            label=f"Unlock <b>{self._app_name}</b>",
            use_markup=True,
            css_classes=["title-2"],
        ))

        # ── Input / spinner stack ─────────────────────────────────────
        self._stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)

        input_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)

        if self._method in ("password", "both"):
            if self._method == "both":
                hint = Gtk.Label(
                    label="Fingerprint will be scanned after you confirm the password.",
                    css_classes=["dim-label", "caption"],
                    wrap=True,
                )
                input_box.append(hint)
            self._pw_entry = Gtk.PasswordEntry(show_peek_icon=True,
                                               placeholder_text="Password")
            self._pw_entry.connect("activate", self._submit)
            input_box.append(self._pw_entry)

            submit_btn = Gtk.Button(
                label="Verify & Unlock" if self._method == "both" else "Unlock",
                halign=Gtk.Align.CENTER,
                css_classes=["suggested-action", "pill"],
            )
            submit_btn.connect("clicked", self._submit)
            input_box.append(submit_btn)

        # fingerprint-only: show a spinner immediately — no button needed
        # the scan starts as soon as the dialog is presented

        spin_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10,
                           halign=Gtk.Align.CENTER)
        self._spinner = Gtk.Spinner(spinning=False)
        self._spinner.set_size_request(44, 44)
        self._spin_lbl = Gtk.Label(label="Authenticating…",
                                   css_classes=["dim-label"])
        spin_box.append(self._spinner)
        spin_box.append(self._spin_lbl)

        if self._method == "fingerprint":
            # Show the spinner view directly; no input page needed
            self._stack.add_named(spin_box, "spin")
        else:
            self._stack.add_named(input_box, "input")
            self._stack.add_named(spin_box, "spin")

        body.append(self._stack)
        outer.append(body)

    def _cancel(self, _):
        self.close()
        if self._on_cancel:
            self._on_cancel()

    def present(self, parent):
        super().present(parent)
        # For fingerprint-only mode start the scan as soon as the dialog
        # appears — user just needs to place their finger, no button click.
        if self._method == "fingerprint":
            GLib.idle_add(self._start_auth, None)

    def _submit(self, _):
        """Called by the Unlock / Verify & Unlock button (password / both modes)."""
        password = None
        if self._method in ("password", "both"):
            password = self._pw_entry.get_text()
            if not password:
                self.toasts.add_toast(Adw.Toast(title="Enter your password."))
                return
        self._start_auth(password)

    def _start_auth(self, password):
        self._stack.set_visible_child_name("spin")
        self._spinner.start()
        spin_text = {
            "fingerprint": "Place your finger on the sensor…",
            "password":    "Verifying password…",
            "both":        "Scanning fingerprint + verifying password…",
        }.get(self._method, "Authenticating…")
        self._spin_lbl.set_text(spin_text)

        def work():
            if self._method == "fingerprint":
                GLib.idle_add(
                    self._spin_lbl.set_text,
                    "Place your finger on the sensor…",
                )
            pp = get_passphrase(self._app_id, password=password)
            GLib.idle_add(self._done, pp)

        threading.Thread(target=work, daemon=True).start()

    def _done(self, passphrase):
        self._spinner.stop()
        if passphrase:
            self.close()
            self._on_success(passphrase)
        else:
            if self._method == "fingerprint":
                self._spin_lbl.set_text("Not recognised — try again…")
                self._spinner.start()
                GLib.timeout_add(1800, lambda: self._start_auth(None) or False)
            else:
                self._stack.set_visible_child_name("input")
                self.toasts.add_toast(Adw.Toast(
                    title="Authentication failed. Try again.", timeout=3,
                ))


# ── Protect Wizard ────────────────────────────────────────────────────────────

class ProtectWizard(Adw.Dialog):
    """3-step wizard: choose app → configure → confirm & run."""

    def __init__(self, parent: SPPMainWindow):
        super().__init__(title="Protect App")
        self.set_content_width(520)
        self.set_content_height(580)
        self.win = parent
        self._app  = None
        self._auth = "fingerprint"
        self._enc  = True

        self.nav = Adw.NavigationView()
        self.set_child(self.nav)
        self._push_step1()

    # ── Step 1 ────────────────────────────────────────────────────────

    def _push_step1(self):
        page = Adw.NavigationPage(title="Choose App")
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        hb = Adw.HeaderBar()
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda _: self.close())
        hb.pack_start(cancel)
        outer.append(hb)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                       margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        body.append(self._steps(1))

        search = Gtk.SearchEntry(placeholder_text="Search…")
        search.connect("search-changed", self._filter)
        body.append(search)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        self.list1 = Gtk.ListBox()
        self.list1.add_css_class("boxed-list")
        self.list1.set_selection_mode(Gtk.SelectionMode.SINGLE)
        scroll.set_child(self.list1)
        body.append(scroll)

        self.spinner1 = Gtk.Spinner(spinning=True, halign=Gtk.Align.CENTER)
        body.append(self.spinner1)

        nxt = Gtk.Button(label="Next →", halign=Gtk.Align.END)
        nxt.add_css_class("suggested-action")
        nxt.add_css_class("pill")
        nxt.connect("clicked", self._step1_next)
        body.append(nxt)

        outer.append(body)
        page.set_child(outer)
        self.nav.push(page)
        threading.Thread(target=self._load_apps, daemon=True).start()

    def _load_apps(self):
        apps = get_all_apps()
        protected_ids = {a["id"] for a in list_apps()}
        available = [a for a in apps if a["id"] not in protected_ids]
        GLib.idle_add(self._fill_list, available)

    def _fill_list(self, apps):
        self.spinner1.stop()
        self.spinner1.set_visible(False)
        self._apps_cache = apps
        if not apps:
            self.list1.append(Adw.ActionRow(title="All installed apps are already protected."))
            return
        for a in apps:
            row = Adw.ActionRow(title=a["name"],
                                subtitle=f"{a['type'].upper()}  ·  {a.get('data_path','')[:48]}")
            ico = _load_icon(a, 32)
            ico.set_valign(Gtk.Align.CENTER)
            row.add_prefix(ico)
            row.app_data = a
            self.list1.append(row)

    def _filter(self, entry):
        q = entry.get_text().lower()
        r = self.list1.get_first_child()
        while r:
            r.set_visible(not q or (hasattr(r, "app_data") and q in r.app_data["name"].lower()))
            r = r.get_next_sibling()

    def _step1_next(self, _):
        sel = self.list1.get_selected_row()
        if not sel or not hasattr(sel, "app_data"):
            self.win.toast("Select an app first.")
            return
        self._app = sel.app_data
        self._push_step2()

    # ── Step 2 ────────────────────────────────────────────────────────

    def _push_step2(self):
        page = Adw.NavigationPage(title="Configure")
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        outer.append(Adw.HeaderBar())

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16,
                       margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        body.append(self._steps(2))

        # App card
        app_row = Adw.ActionRow(title=self._app["name"],
                                subtitle=self._app.get("data_path","")[:52])
        ico = _load_icon(self._app, 40)
        ico.set_valign(Gtk.Align.CENTER)
        app_row.add_prefix(ico)
        app_row.add_css_class("card")
        body.append(app_row)

        # Auth
        g1 = Adw.PreferencesGroup(title="Authentication")
        fp_ok = is_fingerprint_available()
        self._auth_opts = []
        strings = Gtk.StringList()
        if fp_ok:
            strings.append("🖐  Fingerprint")
            self._auth_opts.append("fingerprint")
        strings.append("🔑  Password (PAM)")
        self._auth_opts.append("password")
        if fp_ok:
            strings.append("🖐 + 🔑  Both")
            self._auth_opts.append("both")
        self.auth_combo = Adw.ComboRow(title="Method", model=strings)
        g1.add(self.auth_combo)
        if not fp_ok:
            g1.add(Adw.ActionRow(
                title="Fingerprint not enrolled",
                subtitle="Only password auth available",
                icon_name="dialog-warning-symbolic",
            ))
        body.append(g1)

        # Encryption
        g2 = Adw.PreferencesGroup(title="Encryption")
        self.enc_switch = Adw.SwitchRow(
            title="Encrypt app data",
            subtitle="gocryptfs vault secured with a GPG key",
            active=True,
        )
        g2.add(self.enc_switch)
        body.append(g2)

        # Password entry — shown for password/both modes; hidden for fingerprint
        self._pw_group = Adw.PreferencesGroup(
            title="Set Password",
            description="The vault key is derived from this password via PBKDF2-SHA256 (600 000 iterations). It is never stored.",
        )
        self._pw_entry_row = Adw.PasswordEntryRow(title="Password")
        self._pw_confirm_row = Adw.PasswordEntryRow(title="Confirm password")
        self._pw_group.add(self._pw_entry_row)
        self._pw_group.add(self._pw_confirm_row)
        body.append(self._pw_group)
        self._pw_group.set_visible(False)

        # Show/hide password group based on auth selection
        self.auth_combo.connect("notify::selected", self._on_auth_changed)

        nxt = Gtk.Button(label="Next →", halign=Gtk.Align.END)
        nxt.add_css_class("suggested-action")
        nxt.add_css_class("pill")
        nxt.connect("clicked", self._step2_next)
        body.append(nxt)

        outer.append(body)
        page.set_child(outer)
        self.nav.push(page)

    def _on_auth_changed(self, combo, _):
        method = self._auth_opts[combo.get_selected()]
        self._pw_group.set_visible(method in ("password", "both"))

    def _step2_next(self, _):
        self._auth = self._auth_opts[self.auth_combo.get_selected()]
        self._enc  = self.enc_switch.get_active()
        self._password = None

        if self._auth in ("password", "both"):
            pw  = self._pw_entry_row.get_text()
            pw2 = self._pw_confirm_row.get_text()
            if not pw:
                self.win.toast("Enter a password.")
                return
            if pw != pw2:
                self.win.toast("Passwords do not match.")
                return
            if len(pw) < 8:
                self.win.toast("Password must be at least 8 characters.")
                return
            self._password = pw

        self._push_step3()

    # ── Step 3 ────────────────────────────────────────────────────────

    def _push_step3(self):
        page = Adw.NavigationPage(title="Confirm")
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        outer.append(Adw.HeaderBar())

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16,
                       margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        body.append(self._steps(3))

        # Summary
        g = Adw.PreferencesGroup(title="Summary")
        g.add(Adw.ActionRow(title="App", subtitle=self._app["name"],
                            icon_name="application-x-executable-symbolic"))
        auth_lbl = {"fingerprint": "Fingerprint", "password": "Password (PAM)",
                    "both": "Fingerprint + Password"}
        g.add(Adw.ActionRow(title="Authentication", subtitle=auth_lbl[self._auth],
                            icon_name="fingerprint-symbolic"))
        g.add(Adw.ActionRow(
            title="Encryption",
            subtitle="gocryptfs + GPG  ✓" if self._enc else "Disabled (not recommended)",
            icon_name="security-high-symbolic" if self._enc else "security-low-symbolic",
        ))
        if self._app.get("data_path"):
            g.add(Adw.ActionRow(title="Data path", subtitle=self._app["data_path"],
                                icon_name="folder-symbolic"))
        body.append(g)

        if not self._enc:
            body.append(Adw.Banner(
                title="Without encryption, data is not protected on disk.",
                revealed=True,
            ))

        # Action area: button ↔ spinner+label
        self.action_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)

        go_btn = Gtk.Button(label="🔒  Protect App", halign=Gtk.Align.CENTER)
        go_btn.add_css_class("suggested-action")
        go_btn.add_css_class("pill")
        go_btn.connect("clicked", self._run)
        self.action_stack.add_named(go_btn, "btn")

        prog = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8,
                       halign=Gtk.Align.CENTER)
        sp = Gtk.Spinner(spinning=True)
        sp.set_size_request(32, 32)
        self.prog_lbl = Gtk.Label(label="Working…")
        self.prog_lbl.add_css_class("dim-label")
        prog.append(sp)
        prog.append(self.prog_lbl)
        self.action_stack.add_named(prog, "prog")

        body.append(self.action_stack)
        outer.append(body)
        page.set_child(outer)
        self.nav.push(page)

    def _run(self, _):
        self.action_stack.set_visible_child_name("prog")
        app = self._app

        def work():
            ok, msg = protect_app(app, auth_method=self._auth, encrypt_data=self._enc,
                                  username=os.environ.get("USER", ""),
                                  password=self._password)
            GLib.idle_add(self._finish, ok, msg)

        threading.Thread(target=work, daemon=True).start()

    def _finish(self, ok: bool, msg: str):
        if ok:
            self.win.toast(msg)
            self.win.refresh()
            self.close()
        else:
            self.action_stack.set_visible_child_name("btn")
            self.win.toast(f"Error: {msg}", timeout=6)

    # ── Step indicator ────────────────────────────────────────────────

    def _steps(self, current: int) -> Gtk.Widget:
        box = Gtk.Box(spacing=4, halign=Gtk.Align.CENTER, margin_bottom=4)
        labels = ["Choose", "Configure", "Confirm"]
        for i, lbl in enumerate(labels, 1):
            vb = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3,
                         halign=Gtk.Align.CENTER)
            circle = Gtk.Label(label="✓" if i < current else str(i))
            circle.add_css_class("step-circle")
            circle.add_css_class(
                "step-done" if i < current else
                ("step-active" if i == current else "step-inactive")
            )
            circle.set_size_request(26, 26)
            text = Gtk.Label(label=lbl)
            text.add_css_class("caption")
            if i != current:
                text.add_css_class("dim-label")
            vb.append(circle)
            vb.append(text)
            box.append(vb)
            if i < 3:
                sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL,
                                    valign=Gtk.Align.START, margin_top=13)
                sep.set_size_request(36, -1)
                box.append(sep)
        return box


# ── Setup Dialog ──────────────────────────────────────────────────────────────

class SetupDialog(Adw.Dialog):
    def __init__(self, parent: SPPMainWindow):
        super().__init__(title="Setup")
        self.set_content_width(480)
        self.set_content_height(520)
        self.win = parent

        self.toasts = Adw.ToastOverlay()
        self.set_child(self.toasts)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.toasts.set_child(outer)

        hb = Adw.HeaderBar()
        outer.append(hb)

        page = Adw.PreferencesPage()
        outer.append(page)

        # ── Dependencies ──────────────────────────────────────────────
        dep_group = Adw.PreferencesGroup(
            title="Dependencies",
            description="Required system tools",
        )
        missing = check_dependencies()
        for dep in ["fprintd-verify", "gpg", "gocryptfs", "fusermount", "zenity"]:
            ok = dep not in missing
            row = Adw.ActionRow(title=dep, icon_name="emblem-ok-symbolic" if ok else "dialog-error-symbolic")
            lbl = Gtk.Label(label="Installed" if ok else "Missing")
            lbl.add_css_class("success" if ok else "error")
            lbl.add_css_class("caption")
            row.add_suffix(lbl)
            dep_group.add(row)

        if missing:
            irow = Adw.ActionRow(title="Install missing dependencies",
                                 icon_name="system-software-install-symbolic",
                                 activatable=True)
            self.install_spinner = Gtk.Spinner(valign=Gtk.Align.CENTER)
            irow.add_suffix(self.install_spinner)
            ibtn = Gtk.Button(label="Install", valign=Gtk.Align.CENTER)
            ibtn.add_css_class("suggested-action")
            ibtn.add_css_class("pill")
            ibtn.connect("clicked", self._on_install)
            irow.add_suffix(ibtn)
            dep_group.add(irow)

        page.add(dep_group)

        # ── Authentication ─────────────────────────────────────────────
        auth_group = Adw.PreferencesGroup(title="Authentication")
        fp_ok = is_fingerprint_available()
        fp_row = Adw.ActionRow(title="Fingerprint sensor",
                               subtitle="via fprintd",
                               icon_name="fingerprint-symbolic")
        fp_lbl = Gtk.Label(label="Available" if fp_ok else "Not enrolled")
        fp_lbl.add_css_class("success" if fp_ok else "warning")
        fp_lbl.add_css_class("caption")
        fp_row.add_suffix(fp_lbl)
        auth_group.add(fp_row)

        if not fp_ok:
            cmd_row = Adw.ActionRow(
                title="Enroll fingerprint",
                subtitle="Run in terminal: fprintd-enroll",
                icon_name="dialog-information-symbolic",
            )
            copy_btn = Gtk.Button(icon_name="edit-copy-symbolic",
                                  valign=Gtk.Align.CENTER, tooltip_text="Copy command")
            copy_btn.add_css_class("flat")
            copy_btn.connect("clicked", lambda _: self._copy("fprintd-enroll"))
            cmd_row.add_suffix(copy_btn)
            auth_group.add(cmd_row)

        page.add(auth_group)

        # ── GPG (symmetric) ────────────────────────────────────────────
        import shutil as _shutil
        gpg_group = Adw.PreferencesGroup(title="GPG (Symmetric Encryption)",
                                         description="AES-256 vault keyfile encryption — no key pair needed")
        gpg_ok = bool(_shutil.which("gpg"))
        gpg_row = Adw.ActionRow(
            title="GPG binary",
            subtitle="Available — symmetric AES-256 active" if gpg_ok else "Not found — install gnupg2",
            icon_name="channel-secure-symbolic",
        )
        gpg_lbl = Gtk.Label(label="Ready" if gpg_ok else "Missing")
        gpg_lbl.add_css_class("success" if gpg_ok else "error")
        gpg_lbl.add_css_class("caption")
        gpg_row.add_suffix(gpg_lbl)
        gpg_group.add(gpg_row)
        page.add(gpg_group)

    def _copy(self, text: str):
        Gdk.Display.get_default().get_clipboard().set(text)
        self.toasts.add_toast(Adw.Toast(title="Copied to clipboard"))

    def _on_install(self, btn):
        btn.set_sensitive(False)
        self.install_spinner.start()
        def run():
            ok = install_dependencies()
            GLib.idle_add(lambda: (
                self.toasts.add_toast(Adw.Toast(
                    title="Dependencies installed! Restart the app." if ok
                    else "Installation failed. Try: sudo apt install fprintd gocryptfs gnupg2 zenity fuse"
                ))
            ))
        threading.Thread(target=run, daemon=True).start()



# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    SPPApp().run()


if __name__ == "__main__":
    main()
