#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  exec sudo -E -- "$0" "$@"
fi

BINARY=${1:-./target/release/immunity-ebpf}
BINARY=$(realpath "${BINARY}")
if [[ ! -x ${BINARY} ]]; then
  echo "missing executable: ${BINARY}" >&2
  exit 1
fi
if [[ ! -r /sys/kernel/security/lsm ]] || ! tr ',' '\n' </sys/kernel/security/lsm | grep -qx bpf; then
  echo "SKIP: active kernel LSM list does not include bpf" >&2
  exit 77
fi

workdir=$(mktemp -d /tmp/immunity-lsm.XXXXXX)
target=${workdir}/protected
policy=${workdir}/policy.json
log=${workdir}/agent.log
printf 'baseline\n' >"${target}"
cat >"${policy}" <<EOF
{"version":1,"generation":1,"fail_closed":true,"allow_legacy_tc":false,"interfaces":[],"network_blacklist":[],"blocked_ports":[],"protected_paths":[{"path":"${target}","deny":["write"],"allow_processes":[],"recursive":false}]}
EOF

agent_pid=
cleanup() {
  if [[ -n ${agent_pid} ]] && kill -0 "${agent_pid}" 2>/dev/null; then
    kill -TERM "${agent_pid}" 2>/dev/null || true
    wait "${agent_pid}" 2>/dev/null || true
  fi
  rm -rf -- "${workdir}"
}
trap cleanup EXIT INT TERM

"${BINARY}" --mode enforce --profile server --ai false --metrics-listen off \
  --kernel-policy "${policy}" >"${log}" 2>&1 &
agent_pid=$!

for _ in $(seq 1 50); do
  grep -q 'BPF LSM file guard: true' "${log}" && break
  if ! kill -0 "${agent_pid}" 2>/dev/null; then
    cat "${log}" >&2
    exit 1
  fi
  sleep 0.1
done
grep -q 'BPF LSM file guard: true' "${log}"

if printf 'must-be-blocked\n' >>"${target}" 2>/dev/null; then
  echo "FAIL: BPF LSM allowed a protected write" >&2
  exit 1
fi
grep -qx baseline "${target}"
echo "PASS: BPF LSM denied protected write"
