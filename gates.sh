#!/usr/bin/env bash
# Gate ladder: build (0 warnings) + model spec suite + correspondence.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

dune build --root "$here" @all

for t in test_model test_correspondence; do
  out="$("$here/_build/default/test/$t.exe")"
  echo "$out"
  case "$out" in
    *FAIL*) echo "gate: $t failed"; exit 1 ;;
  esac
done

echo "gates: all green"
