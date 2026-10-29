#!/usr/bin/env bash
# Reproduce the published measurement (50 signed / 50 unsigned / 20 tampered /
# 10 foreign-key / 4 controls / 5 bypass cases + timing). Exit != 0 if any
# acceptance threshold fails.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release --quiet
uname -r
target/release/sxg probe
target/release/sxg-measure --work "${1:-corpus}" --timing "${TIMING:-50}"
