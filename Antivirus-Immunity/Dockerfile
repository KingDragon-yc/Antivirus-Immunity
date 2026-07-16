# syntax=docker/dockerfile:1.7
FROM rust:1.91-bookworm AS builder

RUN rustup component add rustfmt \
    && apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libelf-dev zlib1g-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_NET_RETRY=5 \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
WORKDIR /src
COPY . .
RUN cargo build --locked --release --package antivirus-immunity-ebpf

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && install -d /var/lib/immunity /etc/immunity
COPY --from=builder /src/target/release/immunity-ebpf /usr/local/bin/immunity-ebpf
COPY antivirus-immunity-ebpf/config/kernel-policy.example.json /etc/immunity/kernel-policy.json
COPY antivirus-immunity-ebpf/config/threat-intel.example.json /etc/immunity/threat-intel.json
WORKDIR /var/lib/immunity
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/immunity-ebpf"]
CMD ["--mode", "monitor", "--profile", "container", "--ai", "false", "--interface", "auto", "--metrics-listen", "0.0.0.0:9090", "--kernel-policy", "/etc/immunity/kernel-policy.json", "--threat-intel", "/etc/immunity/threat-intel.json"]
