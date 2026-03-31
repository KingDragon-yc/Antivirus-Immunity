#!/bin/bash
# ==========================================================
# Antivirus-Immunity eBPF — Build Script
# ==========================================================
#
# Prerequisites:
#   - clang >= 12
#   - llvm >= 12
#   - bpftool
#   - libbpf-dev
#   - linux-headers (BTF-enabled kernel >= 5.4)
#   - Rust toolchain (rustup)
#
# Install on Ubuntu/Debian:
#   sudo apt install clang llvm libbpf-dev linux-tools-common bpftool
#
# Install on RHEL/CentOS/AmazonLinux:
#   sudo yum install clang llvm libbpf-devel bpftool
#
# Usage:
#   ./build.sh         # Build all (eBPF probes + Rust userspace)
#   ./build.sh probes  # Build eBPF probes only
#   ./build.sh rust    # Build Rust userspace only
#   ./build.sh clean   # Clean all build artifacts
# ==========================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BPF_DIR="$SCRIPT_DIR/bpf"
BPF_OBJ="$BPF_DIR/probes.bpf.o"
VMLINUX_H="$BPF_DIR/vmlinux.h"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[*]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

# ============================
# Step 0: Check prerequisites
# ============================
check_prereqs() {
    local missing=0

    if ! command -v clang &>/dev/null; then
        error "clang not found. Install: apt install clang"
        missing=1
    fi

    if ! command -v bpftool &>/dev/null; then
        warn "bpftool not found. Skeleton generation will be skipped."
        warn "Install: apt install linux-tools-common bpftool"
    fi

    if [ ! -f "$VMLINUX_H" ]; then
        warn "vmlinux.h not found. Generating from BTF..."
        generate_vmlinux
    fi

    return $missing
}

# ============================
# Generate vmlinux.h from BTF
# ============================
generate_vmlinux() {
    if command -v bpftool &>/dev/null; then
        info "Generating vmlinux.h from kernel BTF..."
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX_H"
        info "vmlinux.h generated ($(wc -l < "$VMLINUX_H") lines)"
    else
        error "Cannot generate vmlinux.h: bpftool not available."
        error "Please install bpftool or provide vmlinux.h manually."
        exit 1
    fi
}

# ============================
# Build eBPF probes
# ============================
build_probes() {
    info "Building eBPF probes..."

    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  TARGET_ARCH="__TARGET_ARCH_x86" ;;
        aarch64) TARGET_ARCH="__TARGET_ARCH_arm64" ;;
        *)       error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    clang -g -O2 -target bpf \
        -D"$TARGET_ARCH" \
        -I "$BPF_DIR" \
        -I /usr/include/bpf \
        -c "$BPF_DIR/probes.bpf.c" \
        -o "$BPF_OBJ"

    info "eBPF object: $BPF_OBJ ($(stat -c%s "$BPF_OBJ") bytes)"

    # Generate skeleton if bpftool is available
    if command -v bpftool &>/dev/null; then
        info "Generating BPF skeleton..."
        bpftool gen skeleton "$BPF_OBJ" > "$BPF_DIR/probes.skel.h"
        info "Skeleton: $BPF_DIR/probes.skel.h"
    fi

    info "eBPF probes built successfully."
}

# ============================
# Build Rust userspace
# ============================
build_rust() {
    info "Building Rust userspace (release)..."
    cd "$SCRIPT_DIR/.."
    cargo build --release -p antivirus-immunity-ebpf
    info "Binary: target/release/immunity-ebpf"
}

# ============================
# Clean
# ============================
clean() {
    info "Cleaning build artifacts..."
    rm -f "$BPF_OBJ" "$BPF_DIR/probes.skel.h"
    cd "$SCRIPT_DIR/.."
    cargo clean -p antivirus-immunity-ebpf
    info "Clean complete."
}

# ============================
# Main
# ============================
case "${1:-all}" in
    probes)
        check_prereqs
        build_probes
        ;;
    rust)
        build_rust
        ;;
    clean)
        clean
        ;;
    all|*)
        check_prereqs
        build_probes
        build_rust
        info ""
        info "Build complete!"
        info "Run: sudo ./target/release/immunity-ebpf --profile server"
        ;;
esac
