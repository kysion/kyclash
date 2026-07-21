#!/usr/bin/env bash
set -euo pipefail

# Loopback-only reliability soak. This deliberately exercises repository-owned
# in-process peers; it never dials a production endpoint or mutates host routes.
# Run from network-sidecar. The default is intentionally short for a disposable
# VM; scheduled/manual CI may raise KYCLASH_SOAK_ROUNDS explicitly.

readonly rounds="${KYCLASH_SOAK_ROUNDS:-10}"
readonly timeout="${KYCLASH_SOAK_TIMEOUT:-120s}"
readonly output="${KYCLASH_SOAK_OUTPUT:-build/reliability-soak}"
readonly go_bin="${GO_BIN:-go}"

if [[ ! "${rounds}" =~ ^[1-9][0-9]*$ || "${rounds}" -gt 1000 ]]; then
  echo "KYCLASH_SOAK_ROUNDS must be an integer in 1..1000" >&2
  exit 64
fi
if ! command -v "${go_bin}" >/dev/null 2>&1; then
  echo "missing Go toolchain: ${go_bin}" >&2
  exit 69
fi

mkdir -p "${output}"
{
  uname -a
  "${go_bin}" version
  printf 'rounds=%s timeout=%s\n' "${rounds}" "${timeout}"
} | tee "${output}/environment.txt"

for round in $(seq 1 "${rounds}"); do
  log="${output}/round-${round}.log"
  echo "[soak] round ${round}/${rounds}"
  "${go_bin}" test -count=1 -timeout="${timeout}" \
    ./internal/carrier \
    ./internal/labserver \
    ./internal/userspace \
    ./internal/wgcarrier 2>&1 | tee "${log}"
done

printf 'passed_rounds=%s\n' "${rounds}" | tee "${output}/summary.txt"
