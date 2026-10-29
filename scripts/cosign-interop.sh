#!/usr/bin/env bash
# Interop check against the real cosign CLI (key-based mode, no transparency
# log, no network for signing/verifying). Fails loudly on any mismatch.
# usage: scripts/cosign-interop.sh [path/to/cosign]
set -euo pipefail
COSIGN=${1:-cosign}
SXG=${SXG:-target/release/sxg}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
command -v "$COSIGN" >/dev/null || { echo "FAIL: cosign not found ($COSIGN)"; exit 1; }
"$COSIGN" version 2>/dev/null | grep -E '^GitVersion' || true
cc -O1 -DTAG='"CO"' -o "$W/ok" fixtures/src/ok.c

# 1) cosign signs -> sxg verifies and runs
( cd "$W" && COSIGN_PASSWORD="" "$COSIGN" generate-key-pair >/dev/null 2>&1 )
COSIGN_PASSWORD="" "$COSIGN" sign-blob --yes --key "$W/cosign.key" --tlog-upload=false \
  --output-signature "$W/ok.sig" "$W/ok" >/dev/null 2>&1
"$SXG" verify --key "$W/cosign.pub" "$W/ok"
out=$("$SXG" run --key "$W/cosign.pub" -- "$W/ok")
[ "$out" = "MARK:OK-CO" ] || { echo "FAIL: gated run printed '$out'"; exit 1; }
echo "PASS cosign-sign -> sxg-verify+run"

# 2) sxg signs -> cosign verifies
"$SXG" keygen "$W/sxg"
"$SXG" sign --key "$W/sxg.key" --out "$W/ok.sxg.sig" "$W/ok"
"$COSIGN" verify-blob --key "$W/sxg.pub" --signature "$W/ok.sxg.sig" --insecure-ignore-tlog=true "$W/ok" 2>&1 | grep -q 'Verified OK'
echo "PASS sxg-sign -> cosign verify-blob"

# 3) negatives: tampered blob rejected by both
cp "$W/ok" "$W/bad"; printf 'X' | dd of="$W/bad" bs=1 seek=200 conv=notrunc 2>/dev/null
if "$SXG" verify --key "$W/cosign.pub" --sig "$W/ok.sig" "$W/bad" 2>/dev/null; then echo "FAIL: sxg accepted tampered"; exit 1; fi
if "$COSIGN" verify-blob --key "$W/sxg.pub" --signature "$W/ok.sxg.sig" --insecure-ignore-tlog=true "$W/bad" >/dev/null 2>&1; then
  echo "FAIL: cosign accepted tampered"; exit 1; fi
echo "PASS tampered rejected by sxg and cosign"
