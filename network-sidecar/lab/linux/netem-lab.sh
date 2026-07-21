#!/usr/bin/env bash
set -euo pipefail

readonly LAB_TABLE="kyclash_lab"
readonly LAB_INTERFACE="${KYCLASH_LAB_INTERFACE:-lo}"
readonly LAB_OUTPUT="${KYCLASH_LAB_OUTPUT:-build/linux-netem}"
readonly LAB_MODE="${1:-run}"

if [[ "${LAB_MODE}" != "run" && "${LAB_MODE}" != "dry-run" ]]; then
  echo "usage: $0 [run|dry-run]" >&2
  exit 64
fi

run() {
  printf '+ '
  printf '%q ' "$@"
  printf '\n'
  if [[ "${LAB_MODE}" == "run" ]]; then
    "$@"
  fi
}

cleanup() {
  if [[ "${LAB_MODE}" != "run" ]]; then
    return
  fi
  tc qdisc del dev "${LAB_INTERFACE}" root 2>/dev/null || true
  nft delete table inet "${LAB_TABLE}" 2>/dev/null || true
}

run_loss_matrix() {
  echo "+ repeat QUIC exchange 20 times; require at least 5 successes under impairment"
  if [[ "${LAB_MODE}" != "run" ]]; then
    return
  fi
  local successes=0
  local failures=0
  local attempt
  for attempt in $(seq 1 20); do
    if KYCLASH_LAB_IMPAIRED=1 go test -count=1 -timeout=10s ./internal/carrier -run TestQUICCarrierAuthenticatesAndReassemblesLargePacket; then
      successes=$((successes + 1))
    else
      failures=$((failures + 1))
    fi
  done
  printf 'impaired QUIC exchanges: successes=%d failures=%d\n' "${successes}" "${failures}"
  if ((successes < 5)); then
    echo "too few successful QUIC exchanges under bounded impairment" >&2
    return 1
  fi
}

if [[ "${LAB_MODE}" == "run" && "$(uname -s)" != "Linux" ]]; then
  echo "refusing to run: this lab is Linux-only" >&2
  exit 69
fi
if [[ "${LAB_INTERFACE}" != "lo" && "${KYCLASH_LAB_ALLOW_NON_LOOPBACK:-}" != "YES" ]]; then
  echo "refusing non-loopback interface without KYCLASH_LAB_ALLOW_NON_LOOPBACK=YES" >&2
  exit 77
fi
if [[ "${LAB_MODE}" == "run" && "${EUID}" -ne 0 ]]; then
  echo "run mode requires root inside a disposable Linux VM" >&2
  exit 77
fi
for tool in go tc nft; do
  if [[ "${LAB_MODE}" == "dry-run" ]]; then
    continue
  fi
  command -v "${tool}" >/dev/null || {
    echo "missing required tool: ${tool}" >&2
    exit 69
  }
done

trap cleanup EXIT INT TERM
run mkdir -p "${LAB_OUTPUT}"

if [[ "${LAB_MODE}" == "run" ]]; then
  {
    uname -a
    go version
    tc -V
    nft --version
  } >"${LAB_OUTPUT}/environment.txt"
fi

run go test -count=3 -timeout=90s ./internal/carrier -run 'Test(QUIC|WSS|TCP)Carrier'

run tc qdisc replace dev "${LAB_INTERFACE}" root netem delay 40ms 15ms distribution normal loss 2% rate 20mbit
run_loss_matrix
run tc qdisc del dev "${LAB_INTERFACE}" root

run nft add table inet "${LAB_TABLE}"
run nft add chain inet "${LAB_TABLE}" output '{ type filter hook output priority 0; policy accept; }'
run nft add rule inet "${LAB_TABLE}" output oifname "${LAB_INTERFACE}" meta l4proto udp reject
run env KYCLASH_LAB_EXPECT_QUIC_BLOCKED=1 go test -count=1 -timeout=30s ./internal/carrier -run TestQUICLabUDPBlocked
run go test -count=3 -timeout=90s ./internal/carrier -run 'Test(WSS|TCP)CarrierAuthenticates'
run nft delete table inet "${LAB_TABLE}"

run go test ./internal/carrier -run '^$' -bench '^BenchmarkQUICCarrierFragmentedRoundTrip$' -benchtime=10s -count=3 -benchmem

if [[ "${LAB_MODE}" == "run" ]]; then
  echo "Linux impaired-network lab passed; raw command output is retained by the invoking terminal/CI log."
fi
