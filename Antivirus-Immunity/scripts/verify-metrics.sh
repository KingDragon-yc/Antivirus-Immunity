#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  exec sudo -E -- "$0" "$@"
fi

BINARY=${1:-./target/release/immunity-ebpf}
BINARY=$(realpath "${BINARY}")
workdir=$(mktemp -d /tmp/immunity-metrics.XXXXXX)
log=${workdir}/agent.log
metrics=${workdir}/metrics.txt
agent_pid=
cleanup() {
  if [[ -n ${agent_pid} ]] && kill -0 "${agent_pid}" 2>/dev/null; then
    kill -TERM "${agent_pid}" 2>/dev/null || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  rm -rf -- "${workdir}"
}
trap cleanup EXIT INT TERM

cd "${workdir}"
"${BINARY}" --mode monitor --profile server --ai false \
  --metrics-listen 127.0.0.1:19090 >"${log}" 2>&1 &
agent_pid=$!

for _ in $(seq 1 50); do
  curl --fail --silent http://127.0.0.1:19090/readyz >/dev/null 2>&1 && break
  if ! kill -0 "${agent_pid}" 2>/dev/null; then
    cat "${log}" >&2
    exit 1
  fi
  sleep 0.1
done
curl --fail --silent http://127.0.0.1:19090/metrics >"${metrics}"
grep -q '^immunity_events_processed_total ' "${metrics}"
grep -q '^immunity_probe_attached{probe="core"} 1$' "${metrics}"
grep -q '^immunity_kernel_ringbuf_dropped_total ' "${metrics}"

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=
grep -q 'eBPF engine stopped gracefully' logs/immunity.jsonl
echo "PASS: Prometheus endpoint and graceful shutdown"
