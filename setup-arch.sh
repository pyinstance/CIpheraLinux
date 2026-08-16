#!/usr/bin/env bash
set -euo pipefail

echo "╭─ CIphera GitHub Beta Setup ──────────────────────╮"
echo "│ Arch Linux / Hyprland                            │"
echo "╰──────────────────────────────────────────────────╯"

sudo pacman -S --needed rust cargo base-devel wl-clipboard

echo
echo "[1/4] Formatting source"
cargo fmt --all

echo "[2/4] Compile check"
cargo check

echo "[3/4] Tests"
cargo test

echo "[4/4] Release build"
cargo build --release

echo
echo "Build complete:"
echo "  ./target/release/ciphera"
echo
echo "Cargo.lock should now exist. Commit it to the repository before publishing a release."
