#!/usr/bin/env bash
# Build the HB_Zayfer WASM module for browser usage.
#
# Prerequisites:
#   cargo install wasm-pack
#   rustup target add wasm32-unknown-unknown
#
# Usage:
#   ./scripts/build-wasm.sh          # build for browser (ESM)
#   ./scripts/build-wasm.sh nodejs   # build for Node.js
#   ./scripts/build-wasm.sh bundler  # build for webpack/rollup

set -euo pipefail

TARGET="${1:-web}"
CRATE="crates/wasm"
OUT_DIR="pkg/wasm"

echo "Building HB_Zayfer WASM for target: $TARGET"

if ! command -v wasm-pack &>/dev/null; then
    echo "wasm-pack not found. Install with: cargo install wasm-pack"
    exit 1
fi

wasm-pack build "$CRATE" \
    --target "$TARGET" \
    --release \
    --out-dir "../../$OUT_DIR" \
    --out-name hb_zayfer

echo ""
echo "Build complete! Output in $OUT_DIR/"
echo ""
echo "Usage (ESM):"
echo "  import init, { aes_gcm_encrypt, sha256, version } from './$OUT_DIR/hb_zayfer.js';"
echo "  await init();"
echo "  console.log(version());"
