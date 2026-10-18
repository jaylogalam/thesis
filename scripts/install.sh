#!/usr/bin/env sh
# Installs `runtime-monitor` into ~/.cargo/bin (Linux/macOS).
set -eu
command -v cargo >/dev/null 2>&1 || { echo "cargo not found. Install Rust: https://rustup.rs" >&2; exit 1; }
cargo install --path "$(dirname "$0")/../app" --locked --force
echo "Installed. Run: runtime-monitor --help   (sudo -E \$(which runtime-monitor) to see all processes)"
