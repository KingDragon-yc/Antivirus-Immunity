#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  exec sudo -E -- "$0" "$@"
fi

BINARY=${1:-./target/release/immunity-ebpf}
INTERFACE=${2:-$(ip route show default | awk 'NR == 1 { print $5 }')}
BINARY=$(realpath "${BINARY}")
if [[ ! -x ${BINARY} ]]; then
  echo "missing executable: ${BINARY}" >&2
  exit 1
fi
if [[ -z ${INTERFACE} ]]; then
  echo "no default-route interface found" >&2
  exit 1
fi

workdir=$(mktemp -d /tmp/immunity-network.XXXXXX)
policy=${workdir}/policy.json
log=${workdir}/agent.log
metrics=${workdir}/metrics.txt
target=198.18.0.1
printf '%s\n' "{\"version\":1,\"generation\":1,\"fail_closed\":true,\"allow_legacy_tc\":false,\"interfaces\":[\"${INTERFACE}\"],\"network_blacklist\":[\"${target}/32\"],\"blocked_ports\":[],\"protected_paths\":[]}" >"${policy}"

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
"${BINARY}" --mode enforce --profile server --ai false \
  --metrics-listen 127.0.0.1:19091 --kernel-policy "${policy}" >"${log}" 2>&1 &
agent_pid=$!

for _ in $(seq 1 50); do
  curl --fail --silent http://127.0.0.1:19091/readyz >/dev/null 2>&1 && break
  if ! kill -0 "${agent_pid}" 2>/dev/null; then
    cat "${log}" >&2
    exit 1
  fi
  sleep 0.1
done
grep -Fq "XDP ingress: [\"${INTERFACE}\"]" "${log}"
grep -Fq "TC egress: [\"${INTERFACE}\"]" "${log}"

ping -I "${INTERFACE}" -c 1 -W 1 "${target}" >/dev/null 2>&1 || true
sleep 1.2
curl --fail --silent http://127.0.0.1:19091/metrics >"${metrics}"
blocked=$(awk '$1 == "immunity_tc_blocked_total" { print $2 }' "${metrics}")
if [[ -z ${blocked} || ${blocked} -lt 1 ]]; then
  cat "${metrics}" >&2
  echo "FAIL: TC did not report blocking the test packet" >&2
  exit 1
fi

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=
if tc filter show dev "${INTERFACE}" egress | grep -q 'pref 1.*handle 0x1'; then
  echo "FAIL: legacy TC filter remained after shutdown" >&2
  exit 1
fi
echo "PASS: XDP/TC attached, TC blocked traffic, and shutdown left no legacy filter"
