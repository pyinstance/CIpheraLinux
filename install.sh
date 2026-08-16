#!/usr/bin/env bash
set -euo pipefail

echo "╭─ CIphera Public Beta Installer ─────────────────────────╮"
echo "│ Security & Breach Scanner                       │"
echo "╰─────────────────────────────────────────────────╯"

if ! command -v cargo >/dev/null 2>&1; then
    echo
    echo "Cargo was not found."
    echo "On Arch Linux run:"
    echo "sudo pacman -S --needed rust cargo base-devel wl-clipboard"
    exit 1
fi

if ! command -v wl-copy >/dev/null 2>&1; then
    echo "Warning: wl-copy not found. On Wayland install wl-clipboard."
fi

cargo build --release
sudo install -Dm755 target/release/ciphera /usr/local/bin/ciphera

echo
echo "CIphera installed successfully."
echo "Launch with: ciphera"
