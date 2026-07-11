# Reproducible builder for the ZiSK guest ELF.
#
# The programVK that ends up pinned on L1 (and in the server's
# `prover_api_config.zisk_program_vk` tripwire) is the ROM merkle root of
# this ELF, so a given source revision must map to exactly one binary.
# Everything that influences the build is pinned here: the base image, the
# cargo-zisk release (which fixes the ZiSK Rust toolchain it installs), the
# committed guest/Cargo.lock, and a fixed /build source path so no host
# paths leak into panic messages.
#
# Build (from the repo root; see build-guest.sh for the one-command wrapper):
#   docker build -f docker/guest-builder.Dockerfile -o out .
#   sha256sum out/zksync-os-zisk-guest

FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates xz-utils \
        build-essential git pkg-config libssl-dev \
        openmpi-bin libopenmpi-dev libsodium23 libgmp10 libomp5-18 \
        clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# The `zisk` toolchain installed below provides rustc but no cargo. Rustup's
# cargo fallback only applies to toolchains named stable/beta/nightly, so a
# pinned cargo is copied into the zisk toolchain directly (see below).
# Codegen is entirely the zisk rustc's — cargo only orchestrates — but pin it
# anyway so nothing about the build floats with the image build date.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
        --default-toolchain 1.87.0 --profile minimal
ENV PATH=/root/.cargo/bin:/root/.zisk/bin:$PATH

# cargo-zisk from the pinned release; `toolchain install` fetches the ZiSK
# Rust toolchain matching this cargo-zisk version.
ARG ZISK_VERSION=0.18.0
RUN curl -fsSL -o /tmp/cargo_zisk.tar.gz \
        https://github.com/0xPolygonHermez/zisk/releases/download/v${ZISK_VERSION}/cargo_zisk_linux_amd64.tar.gz \
    && mkdir -p /root/.zisk \
    && tar -xzf /tmp/cargo_zisk.tar.gz -C /root/.zisk \
    && mv /root/.zisk/bin/cargo-zisk-cpu /root/.zisk/bin/cargo-zisk \
    && rm /tmp/cargo_zisk.tar.gz \
    && cargo-zisk --version \
    && cargo-zisk toolchain install \
    && cp /root/.rustup/toolchains/1.87.0-x86_64-unknown-linux-gnu/bin/cargo \
          /root/.rustup/toolchains/zisk/bin/cargo

WORKDIR /build
COPY lib /build/lib
COPY guest /build/guest

RUN cd /build/guest \
    && cargo-zisk build --release \
    && ELF="$(find target -type f -name zksync-os-zisk-guest -path '*/release/*' | head -1)" \
    && test -n "$ELF" \
    && nm -C "$ELF" | grep -q 'ziskos::alloc::embedded_dlmalloc::DLMALLOC' \
    && cp "$ELF" /build/zksync-os-zisk-guest \
    && sha256sum /build/zksync-os-zisk-guest

FROM scratch AS export
COPY --from=builder /build/zksync-os-zisk-guest /zksync-os-zisk-guest
