#!/bin/bash
# SPPLoginMaster - Install Script
set -e

echo "╔═══════════════════════════════════════════╗"
echo "║       SPPLoginMaster  Installer           ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "❌ Python3 non trovato."
    exit 1
fi

# System dependencies
echo "📦 Installazione dipendenze di sistema..."
sudo apt install -y \
    fprintd \
    gocryptfs \
    fuse \
    zenity \
    gnupg2 \
    python3-pip \
    python3-gi \
    python3-gi-cairo \
    gir1.2-gtk-4.0 \
    gir1.2-adw-1 \
    libadwaita-1-dev

# Python dependencies via apt first
echo "🐍 Installazione dipendenze Python..."
sudo apt install -y python3-click python3-rich || \
    pip3 install --user --break-system-packages click rich
 
# Install package
echo "📥 Installazione SPPLoginMaster..."
pip3 install --user --break-system-packages -e .

# Make scripts executable
chmod +x spp-cli spp-gui

# Add to PATH if needed
INSTALL_PATH="$HOME/.local/bin"
if [[ ":$PATH:" != *":$INSTALL_PATH:"* ]]; then
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> ~/.bashrc
    echo "⚠️  Aggiunto ~/.local/bin al PATH. Riavvia il terminale."
fi

# Create .desktop for GUI
mkdir -p ~/.local/share/applications
cat > ~/.local/share/applications/spploginmaster.desktop <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=SPPLoginMaster
Comment=Secure Privacy Protection Login Master
Exec=spp-gui
Icon=security-high
Terminal=false
Categories=Security;System;
EOF

update-desktop-database ~/.local/share/applications/ 2>/dev/null || true

echo ""
echo "✅ SPPLoginMaster installato!"
echo ""
echo "  Avvio GUI:  spp-gui"
echo "  Avvio CLI:  spp-cli --help"
echo "  Setup:      spp-cli setup"
