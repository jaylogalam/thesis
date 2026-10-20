#!/usr/bin/env bash
# Build as the current user, then run the binary as root (fanotify needs it).
# Extra arguments are passed to the app, e.g. ./run.sh --help
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release
exec sudo ./target/release/app "$@"
