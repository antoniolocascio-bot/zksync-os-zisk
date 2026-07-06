# ZiSK Second Proof System for ZKsync OS

A second proof system for ZKsync OS using ZiSK (RV64IMA zkVM). Runs alongside
the primary airbender (RV32I) proof system, providing independent verification
of state transitions.

## Architecture

```
                         ┌─────────────────────────────────┐
                         │     zksync-os-server pipeline    │
                         │                                  │
                         │  BlockExecutor → TreeManager →   │
                         │  ProverInputGenerator → Batcher  │
                         │       │               │          │
                         │  airbender witness  ZiSK input   │
                         │  (Vec<u32>)       (BatchInput)   │
                         └───────┬───────────────┬──────────┘
                                 │               │
                    ┌────────────▼──┐    ┌───────▼────────┐
                    │  Airbender    │    │  ZiSK Prover   │
                    │  RV32I prover │    │  RV64IMA prover│
                    └────────┬──────┘    └───────┬────────┘
                             │                   │
                    ┌────────▼───────────────────▼────────┐
                    │        L1 Smart Contract             │
                    │  Verifies BOTH proofs for each batch │
                    └─────────────────────────────────────┘
```

## Directory Structure

| Directory | What it is |
|-----------|-----------|
| `lib/` | Shared Rust library — REVM executor, merkle proof verification, batch commitment hashing, types. Used by the guest and the server. |
| `guest/` | ZiSK guest binary — compiled to RV64IMA ELF, runs inside the prover. Reads `BatchInput`, executes with proof verification, commits the batch hash. |
Solidity verifiers (`ZiskVerifier.sol`, `ZiskSnarkPlonkVerifier.sol`) live in [era-contracts](https://github.com/vladbochok/era-contracts/tree/vb/zisk-verifier/l1-contracts/contracts/state-transition/verifiers) and are generated via `cargo run -- --variant zisk` in `era-contracts/tools/verifier-gen/`.

## What the ZiSK Proof Verifies

Every storage read is verified against a Blake2s merkle proof that recovers
the expected state root. The proof commits a `BatchPublicInput` hash:

- **State before**: Blake2s(tree_root, leaf_count, block_number, block_hashes_blake, timestamp)
- **State after**: Computed from REVM execution + tree update proof
- **Batch hash**: Keccak256(chain_id, timestamps, DA commitment, tx counts, priority ops hash, L2 logs root, ...)
- **Committed output**: Keccak256(state_before || state_after || batch_hash)

Verified inside the proof:
- Storage reads via merkle proofs (every SLOAD)
- Account balances/nonces via preimage hash verification
- L2 transaction signatures via secp256k1 ecrecover
- L1 transaction hash binding (keccak256(encoded_tx) == l1_tx_hash)
- Bytecode integrity (keccak256(code) == code_hash)
- Block header hash from execution results (RLP + keccak256)
- Tree update entries cross-checked against REVM execution diffs

## Server Integration

Enable the second proof system in server config:

```yaml
prover_input_generator:
  second_proof_system: true
```

This generates ZiSK prover input alongside the primary airbender witness
for every block. The ZiSK input includes merkle proofs, account preimages,
and a tree update proof extracted from the server's merkle tree.

## Development

```bash
# Run lib tests (includes the proven-path end-to-end tests)
cd lib && cargo test

# Generate a minimal ZiSK input natively (writes /tmp/proven_input.bin)
cd lib && cargo test export_proven_input_for_emulator
# Print the native reference commitment for those exact bytes
cd lib && cargo test print_input_bin_commitment -- --ignored

# Build guest for ZiSK prover
cargo-zisk build --release   # in guest/

# Run in ZiSK emulator
cargo-zisk execute -e guest/target/riscv64ima-zisk-zkvm-elf/release/zksync-os-zisk-guest -i /tmp/proven_input.bin

# Verify ZiSK constraints (without full proving)
cargo-zisk verify-constraints -e <elf> -i input.bin

# Full proof generation (requires 64GB+ RAM)
./prove_and_verify.sh --input batch.json
```

## Testing

```bash
# Server integration tests (all 3 ZiSK tests)
cd ../zksync-os-server
cargo nextest run -p zksync_os_integration_tests --profile no-pig -E 'test(zisk)'
```
