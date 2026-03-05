#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -d "dist" ]]; then
  echo "minify-dist: missing dist/ (run 'trunk build --release' first)" >&2
  exit 2
fi

if ! command -v node >/dev/null 2>&1; then
  echo "minify-dist: node is required" >&2
  exit 2
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "minify-dist: npm is required (to install esbuild)" >&2
  exit 2
fi

TOOL_DIR="$ROOT/tools/minify_dist"
if [[ ! -d "$TOOL_DIR/node_modules" ]]; then
  echo "minify-dist: installing tools/minify_dist deps..." >&2
  npm --prefix "$TOOL_DIR" ci
fi

node "$TOOL_DIR/minify_dist.mjs" "$ROOT/dist" "$@"
