#!/usr/bin/env bash
# Gate ladder: build (0 warnings) + model spec suite + correspondence.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

dune build --root "$here" @all

for t in test_model test_correspondence test_reader test_utf8 test_msgpack test_encode test_forward test_ack test_detect test_pan test_ssn test_aws_key test_base58 test_sol_pubkey test_eth_address; do
  rc=0
  out="$("$here/_build/default/test/$t.exe" 2>&1)" || rc=$?
  echo "$out"
  case "$out" in
    *FAIL*) echo "gate: $t failed"; exit 1 ;;
  esac
  if [ "$rc" -ne 0 ]; then echo "gate: $t exited $rc"; exit 1; fi
done

echo "gates: all green"
