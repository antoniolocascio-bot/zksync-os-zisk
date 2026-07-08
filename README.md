# ZKsync OS: ZiSK Prover

This repo contains the Prover Service implementation for ZKsync OS ZiSK (RV64IMA) prover — the second proof system alongside Airbender.

## Overview

The ZiSK prover generates STARK + SNARK proofs for ZKsync OS batches using the ZiSK zkVM. It runs as an external service that polls the sequencer for work, generates proofs via `cargo-zisk`, and submits them back for multi-proof composition with Airbender.

### Architecture

```
Sequencer (zksync-os-server)
    │
    ├── /ZiSK/pick  → ZiSK batch data (BatchInput, bincode)
    │
    └── /ZiSK/submit ← ZiSK SNARK proof (768 bytes) + public values (256 bytes)
                         │
                         ▼
              MultiProofSnarkProof (Airbender + ZiSK combined)
                         │
                         ▼
                    L1 verification
```

### Proof Pipeline

At startup the service runs a one-time `cargo-zisk program-setup` for the guest ELF (ROM setup; cheap when already cached). For each batch it then runs a single integrated `cargo-zisk prove --plonk` subprocess (ZiSK v0.18.0) that:

1. Executes the ZiSK guest ELF and generates + aggregates per-AIR proofs into a verified vadcop final proof.
2. Wraps it into a BN254 Plonk SNARK suitable for on-chain verification.

The output file is parsed into the 768-byte SNARK proof and the 256-byte public values (`program VK ‖ publics ‖ vadcop-final VK`) the sequencer expects. On an RTX 5090, proving runs from ~12 s (small batch) to ~80 s (1000-transfer batch), dominated by the STARK phase; the Plonk wrap is ~5–7 s and batch-size independent. GPU acceleration is used when started with GPU enabled (default).

## Prerequisites

- **ZiSK toolchain v0.18.0**: `cargo-zisk` in PATH ([install](https://github.com/0xPolygonHermez/zisk))
- **ZiSK guest ELF**: Built from `zksync-os-zisk/guest/` via `cargo-zisk build --release`
- **STARK proving key**: `~/.zisk/provingKey/` (via `ziskup`)
- **PLONK proving key**: `~/.zisk/provingKeySnark/` (via `ziskup setup_snark`)
- **libgmp-dev**: required by `program-setup`'s assembly RomSetup (`-lgmp`/`-lgmpxx`)
- **GPU**: NVIDIA with 16GB+ VRAM (CUDA required for GPU mode)

## Usage

Before starting, make sure your **sequencer** has ZiSK proving enabled:

```yaml
prover_input_generator:
  second_proof_system: true
```

### Start the prover service

```bash
cargo run --release -- \
  --sequencer-url http://localhost:3124 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path /path/to/zksync-os-zisk-guest \
  --proving-key ~/.zisk/provingKey \
  --proving-key-plonk ~/.zisk/provingKeySnark
```

### With authentication

```bash
cargo run --release -- \
  --sequencer-url http://user:password@sequencer.example.com:3124 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path /path/to/zksync-os-zisk-guest \
  --proving-key ~/.zisk/provingKey \
  --proving-key-plonk ~/.zisk/provingKeySnark
```

### With VK hash filtering

Only prove batches matching specific verification key hashes:

```bash
cargo run --release -- \
  --sequencer-url http://localhost:3124 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path /path/to/zksync-os-zisk-guest \
  --proving-key ~/.zisk/provingKey \
  --proving-key-plonk ~/.zisk/provingKeySnark \
  --supported-vk 0x21a582e2fb44e0732b565ffe36331ffb77a315870076b1dc1556579bbc4a67b2
```

Or load from a file:

```bash
cargo run --release -- \
  ... \
  --vk-hashes-file supported_vk_hashes.txt
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--sequencer-url` | required | Sequencer URL. Supports `http://user:pass@host:port`. |
| `--zisk-binary` | required | Path to `cargo-zisk` binary. |
| `--elf-path` | required | Path to ZiSK guest ELF. |
| `--proving-key` | required | STARK proving key directory. |
| `--proving-key-plonk` | required | PLONK proving key directory (alias: `--proving-key-snark`). |
| `--no-gpu` | (off) | Run `cargo-zisk` CPU-only. |
| `--asm-emulator` | (off) | Use the ASM emulator for witness generation (faster; needs a high memlock ulimit). Default is the standard emulator. |
| `--work-dir` | `/tmp/zisk_proofs` | Intermediate proof files (cleaned after each proof). |
| `--poll-interval-secs` | `5` | Seconds between polls when no work available. |
| `--iterations` | `0` | Exit after N proofs (0 = unlimited). |
| `--supported-vk` | (none) | Accepted VK hashes. Repeatable. Empty = accept all. |
| `--vk-hashes-file` | (none) | File with VK hashes (one per line, # comments). |
| `--metrics-address` | `0.0.0.0:3313` | Prometheus metrics endpoint. |
| `--prover-id` | hostname | Identity reported to the sequencer's job API; shows up in server-side assignment/reassignment logs. |

### Metrics

Prometheus metrics are served at `--metrics-address` (default `:3313`):

| Metric | Type | Description |
|--------|------|-------------|
| `zisk_prover_http_latency` | Histogram | HTTP pick/submit latency |
| `zisk_prover_proof_generation_time` | Histogram | Total proof time per batch |
| `zisk_prover_prove_time` | Histogram | `cargo-zisk prove` subprocess time (STARK + PLONK wrap) |
| `zisk_prover_program_setup_time` | Histogram | One-time per-ELF `program-setup` duration |
| `zisk_prover_proofs` | Counter | Proof attempts by outcome (success/failure/cancelled) |

## Fleet deployment (multiple GPUs / machines)

The sequencer's ZiSK job API is a job market: each daemon independently picks
a batch, proves it, and submits. Scaling out is running more daemons — the
server handles concurrent picks, per-assignment timeouts, and reassignment of
jobs whose prover disappeared. There is no coordination between daemons.

One daemon per GPU:

```bash
# Machine A, GPU 0
CUDA_VISIBLE_DEVICES=0 zksync-os-zisk-prover-service \
  --sequencer-url http://sequencer:3124 \
  --work-dir /tmp/zisk_proofs_gpu0 --metrics-address 0.0.0.0:3313 \
  --zisk-binary ... --elf-path ... --proving-key ... --proving-key-plonk ...

# Machine A, GPU 1 — distinct work dir and metrics port
CUDA_VISIBLE_DEVICES=1 zksync-os-zisk-prover-service \
  --sequencer-url http://sequencer:3124 \
  --work-dir /tmp/zisk_proofs_gpu1 --metrics-address 0.0.0.0:3314 \
  --prover-id machine-a-gpu1 \
  ...
```

Per-daemon requirements on a shared box: a distinct `--work-dir` (proof
scratch would collide), a distinct `--metrics-address` port, and
`CUDA_VISIBLE_DEVICES` pinning one GPU per daemon. `--prover-id` defaults to
the hostname; set it explicitly when several daemons share a machine.

Per-box (shared between daemons): the proving keys, the guest ELF, and the
`program-setup` cache — run one daemon first to completion of program-setup,
or pre-run `cargo-zisk rom-setup`, before starting the rest.

Server side: set the sequencer's ZiSK assignment timeout comfortably above
the worst-case proving time for your batch sizes, or jobs will be reassigned
mid-proof and the late submission rejected as `UnknownJob` (harmless, but
wasted work). Fleet members running a stale guest build are caught by the
server's VK drift tripwire (`zisk_lane_vk_drift`) when `zisk_program_vk` is
configured.

## License

ZKsync OS repositories are distributed under the terms of either

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/blog/license/mit/>)

at your option.
