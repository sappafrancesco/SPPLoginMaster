"""
SPPLoginMaster - CLI Interface
"""

import os
import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.prompt import Prompt, Confirm
from spp.apps import get_all_apps
from spp.config import list_apps, get_app_config
from spp.protect import protect_app, unprotect_app, mount_app, unmount_app
from spp.security import (
    check_dependencies, install_dependencies,
    is_fingerprint_available,
    unmount_all,
)

console = Console()

BANNER = """
[bold cyan]╔═══════════════════════════════════════════╗
║   [white]SPP[/white][cyan]Login[/cyan][white]Master[/white]  [dim]v1.0.0[/dim]              ║
║   [dim]Secure Privacy Protection for Linux[/dim]    ║
╚═══════════════════════════════════════════╝[/bold cyan]
"""


@click.group()
def main():
    """SPPLoginMaster - Protect your apps with fingerprint or password."""
    pass


@main.command()
def setup():
    """Initial setup: check dependencies, configure GPG key."""
    console.print(BANNER)
    console.print("[bold]🔧 SSPPLoginMaster Initial setup[/bold]\n")

    # Check dependencies
    console.print("[cyan]Dependencies check...[/cyan]")
    missing = check_dependencies()
    if missing:
        console.print(f"[yellow]Missing dependencies: {', '.join(missing)}[/yellow]")
        if Confirm.ask("Do you want to install them now?"):
            ok = install_dependencies()
            if ok:
                console.print("[green]✅ Dependencies installed.[/green]")
            else:
                console.print("[red]❌ Error during installation. Manually try:[/red]")
                console.print(f"  sudo apt install {' '.join(missing)}")
                sys.exit(1)
    else:
        console.print("[green]✅ All dependencies already installed.[/green]")

    # Check fingerprint
    if is_fingerprint_available():
        console.print("[green]✅ Fingerprint available.[/green]")
    else:
        console.print("[yellow]⚠️  No fingerprint enrolled. Use password-based login or enroll one.[/yellow]")

    import shutil
    if shutil.which("gpg"):
        console.print("[green]✅ GPG (symmetric encryption) available.[/green]")
    else:
        console.print("[red]❌ GPG not found — install gnupg2.[/red]")
        sys.exit(1)

    console.print("\n[bold green]✅ Setup completed! Use 'spp-cli protect' to protect an application.[/bold green]")


@main.command()
@click.option("--app-id", "-a", default=None, help="App's ID")
@click.option("--auth", "-m", type=click.Choice(["fingerprint", "password", "both"]),
              default=None, help="Authentication method")
@click.option("--no-encrypt", is_flag=True, default=False,
              help="Don't encrypt data, just protect launching (not reccomended, vulnerable)")
def protect(app_id, auth, no_encrypt):
    """Protect an app with fingerprint/password."""
    console.print(BANNER)

    # List available apps
    apps = get_all_apps()

    if not app_id:
        console.print("[bold]📦 Available apps:[/bold]\n")
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Type", style="yellow")
        table.add_column("Data", style="dim")

        for i, app in enumerate(apps):
            already = "🔒 " if get_app_config(app["id"]) else ""
            table.add_row(
                str(i + 1),
                app["id"],
                f"{already}{app['name']}",
                app["type"],
                app.get("data_path", "N/A")[:40]
            )
        console.print(table)

        choice = Prompt.ask("\nNumber or app ID", default="")
        if not choice:
            return

        try:
            idx = int(choice) - 1
            selected_app = apps[idx]
        except (ValueError, IndexError):
            selected_app = next((a for a in apps if a["id"] == choice), None)
            if not selected_app:
                console.print("[red]App not found.[/red]")
                return
    else:
        selected_app = next((a for a in apps if a["id"] == app_id), None)
        if not selected_app:
            console.print(f"[red]App '{app_id}' not found.[/red]")
            return

    # Auth method
    if not auth:
        fp_available = is_fingerprint_available()
        console.print(f"\n[bold]🔐 Authentication method for [cyan]{selected_app['name']}[/cyan]:[/bold]")
        if fp_available:
            console.print("  1. Fingerprint")
            console.print("  2. Password")
            console.print("  3. Both (fingerprint + password)")
            choice = Prompt.ask("Choiche", choices=["1", "2", "3"], default="1")
            auth = {"1": "fingerprint", "2": "password", "3": "both"}[choice]
        else:
            console.print("[yellow]⚠️  Fingerprint not available. Will use password-based authentication.[/yellow]")
            auth = "password"

    # Encryption
    encrypt = not no_encrypt
    if encrypt:
        encrypt = Confirm.ask(
            f"\nEncrypt [cyan]{selected_app['name']}[/cyan]'s data with gocryptfs+GPG?",
            default=True
        )

    # Confirm
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  App: [cyan]{selected_app['name']}[/cyan]")
    console.print(f"  Auth: [yellow]{auth}[/yellow]")
    console.print(f"  Encryption: [yellow]{'Sì' if encrypt else 'No'}[/yellow]")
    console.print(f"  Data: [dim]{selected_app.get('data_path', 'N/A')}[/dim]")

    if not Confirm.ask("\nContinue?", default=True):
        return

    with console.status(f"[cyan]Securing {selected_app['name']}...[/cyan]"):
        ok, msg = protect_app(
            selected_app,
            auth_method=auth,
            encrypt_data=encrypt,
            username=os.environ.get("USER", "")
        )

    if ok:
        console.print(f"\n[bold green]{msg}[/bold green]")
    else:
        console.print(f"\n[bold red]❌ {msg}[/bold red]")


@main.command()
@click.argument("app_id", required=False)
def unprotect(app_id):
    """Remove protection from an app."""
    protected = list_apps()
    if not protected:
        console.print("[yellow]No app protected.[/yellow]")
        return

    if not app_id:
        table = Table(box=box.ROUNDED, header_style="bold cyan")
        table.add_column("#")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Auth")
        for i, app in enumerate(protected):
            table.add_row(str(i+1), app["id"], app.get("name",""), app.get("auth_method",""))
        console.print(table)
        choice = Prompt.ask("Number or app's ID")
        try:
            app_id = protected[int(choice)-1]["id"]
        except (ValueError, IndexError):
            app_id = choice

    if not Confirm.ask(f"Remove '{app_id}'\'s protection?", default=False):
        return

    from spp.auth import get_passphrase_interactive
    from spp.config import get_app_config
    cfg = get_app_config(app_id)
    passphrase = None
    if cfg and cfg.get("encrypt_data"):
        console.print("[cyan]Authentication required to decrypt vault...[/cyan]")
        passphrase = get_passphrase_interactive(app_id)
        if not passphrase:
            console.print("[red]❌ Authentication failed.[/red]")
            return

    ok, msg = unprotect_app(app_id, passphrase)
    console.print(f"[green]{msg}[/green]" if ok else f"[red]{msg}[/red]")


@main.command(name="list")
def list_protected():
    """List all protected apps."""
    apps = list_apps()
    if not apps:
        console.print("[yellow]No app protected.[/yellow]")
        return

    table = Table(title="🔒 Protected apps", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Auth", style="yellow")
    table.add_column("Encryption", style="green")
    table.add_column("Mounted", style="blue")

    from spp.security import is_mounted
    from pathlib import Path

    for app in apps:
        mp = app.get("mount_path")
        mounted = "✅" if (mp and is_mounted(Path(mp))) else "❌"
        encrypted = "✅" if app.get("encrypt_data") else "❌"
        table.add_row(
            app["id"], app.get("name",""), app.get("auth_method",""),
            encrypted, mounted
        )
    console.print(table)


@main.command(name="auth-mount")
@click.argument("app_id")
def auth_mount(app_id):
    """
    Authenticate the user and mount the vault.
    Called by wrapper scripts — collects credentials interactively via zenity.
    Exits with code 0 on success, 1 on any auth or mount failure.
    """
    # Verify wrapper script has not been tampered with [SPP-08]
    from spp.launcher import verify_wrapper
    if not verify_wrapper(app_id):
        import subprocess as _sp
        _sp.run(
            ["zenity", "--error", "--title=SPPLoginMaster",
             "--text=⚠️  Security alert: wrapper script integrity check failed.\n"
             "Re-protect the application to restore a trusted launcher."],
            capture_output=True,
        )
        sys.exit(1) 

    # If the vault is already mounted (user pre-authenticated from the GUI),
    # skip the auth dialog — the data is already accessible.
    from spp.config import get_app_config
    from spp.security import is_mounted
    from pathlib import Path as _Path
    _cfg = get_app_config(app_id)
    if _cfg and _cfg.get("encrypt_data") and _cfg.get("mount_path"):
        if is_mounted(_Path(_cfg["mount_path"])):
            sys.exit(0)

    from spp.auth import get_passphrase_interactive
    passphrase = get_passphrase_interactive(app_id)
    if not passphrase:
        sys.exit(1)
    ok, msg = mount_app(app_id, passphrase)
    if not ok:
        console.print(f"[red]{msg}[/red]")
        sys.exit(1)


@main.command()
@click.argument("app_id")
def mount(app_id):
    """Mount encrypted vault (interactive auth via terminal)."""
    from spp.auth import get_passphrase_interactive
    passphrase = get_passphrase_interactive(app_id)
    if not passphrase:
        console.print("[red]❌ Authentication failed.[/red]")
        return
    ok, msg = mount_app(app_id, passphrase)
    console.print(f"[green]{msg}[/green]" if ok else f"[red]{msg}[/red]")


@main.command()
@click.argument("app_id")
def unmount(app_id):
    """Lock (unmount) an app's encrypted vault."""
    ok, msg = unmount_app(app_id)
    console.print(f"[green]{msg}[/green]" if ok else f"[red]{msg}[/red]")


@main.command()
def panic():
    """🚨 Emergency: unmount ALL vaults immediately."""
    console.print("[bold red]🚨 PANIC MODE - Unmount all vaults...[/bold red]")
    results = unmount_all()
    if not results:
        console.print("[yellow]No vaults mounted.[/yellow]")
        return
    for app_id, ok in results:
        status = "[green]✅[/green]" if ok else "[red]❌[/red]"
        console.print(f"  {status} {app_id}")


@main.command(name="repair-wrappers")
def repair_wrappers():
    """Regenerate all wrapper scripts (fixes env issues without touching vaults)."""
    from spp.launcher import create_wrapper_script, compute_wrapper_hmac
    from spp.config import set_app_config
    apps = list_apps()
    if not apps:
        console.print("[yellow]No apps protected.[/yellow]")
        return
    for app in apps:
        try:
            create_wrapper_script(app)
            new_hmac = compute_wrapper_hmac(app["id"])
            app["wrapper_hmac"] = new_hmac
            set_app_config(app["id"], app)
            console.print(f"  [green]✅[/green] {app.get('name', app['id'])}")
        except Exception as e:
            console.print(f"  [red]❌[/red] {app.get('name', app['id'])}: {e}")


@main.command()
def status():
    """Show status of all protected apps."""
    from spp.security import is_mounted
    from pathlib import Path

    apps = list_apps()
    if not apps:
        console.print("[yellow]No app protected.[/yellow]")
        return

    console.print(Panel("[bold cyan]SPPLoginMaster Status[/bold cyan]", expand=False))
    for app in apps:
        mp = app.get("mount_path")
        mounted = is_mounted(Path(mp)) if mp else False
        icon = "🔓" if mounted else "🔒"
        console.print(f"  {icon} [cyan]{app.get('name','?')}[/cyan] [{app.get('auth_method','')}] {'(mounted)' if mounted else '(unmounted)'}")


if __name__ == "__main__":
    main()
