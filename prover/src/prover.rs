//! ZiSK proof generation via `cargo-zisk` subprocesses (ZiSK v0.18.0).
//!
//! v0.18.0 replaces the old two-step flow (`prove --aggregation` +
//! `prove-snark`) with a single integrated `prove --plonk` invocation that
//! takes the batch all the way to a BN254 PLONK SNARK. A one-time
//! `program-setup` per guest ELF generates the ROM setup the prover needs.
//!
//! Three proving flows share the pipeline:
//! - [`ZiskProver::generate_proof`] — per-batch STF proof with the PLONK
//!   wrap (`--plonk`), for the server's per-batch mode.
//! - [`ZiskProver::generate_vadcop_proof`] — per-batch STF proof WITHOUT
//!   `--plonk`: the `vadcop_final` proof stream is kept and submitted so
//!   the aggregator guest can verify it in-zkVM (aggregated mode).
//! - [`ZiskProver::generate_aggregated_proof`] — the aggregator guest over
//!   N per-batch streams, with the PLONK wrap: one range proof for L1.
//!
//! Uses `tokio::process` so subprocess waits can be cancelled instantly
//! via `CancellationToken` — no busy-polling.

use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::metrics::ZISK_PROVER_METRICS;

const ZISK_SNARK_PROOF_BYTES: usize = 768;
// programVK(32) + guest publics(256: ziskos's full 64-word output region,
// the guest's 8 commitment words first, zeros after) + vadcopVK(32).
// A real cargo-zisk v0.18 proof file carries the full 256-byte publics
// region (draft-era code assumed 192 — settled by the first real parse;
// regression-tested against a committed real proof file).
const ZISK_PUBLIC_VALUES_BYTES: usize = 320;
/// Number of u64 words in the guest-ELF ROM root (program VK) and in the
/// vadcop-final verification key.
const PROGRAM_VK_LEN: usize = 4;

#[derive(Debug)]
pub struct ZiskSnarkOutput {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
}

#[derive(Clone)]
pub struct ZiskProver {
    binary: PathBuf,
    elf_path: PathBuf,
    /// The aggregator guest ELF (aggregated mode only).
    aggregator_elf_path: Option<PathBuf>,
    proving_key: PathBuf,
    proving_key_plonk: PathBuf,
    work_dir_base: PathBuf,
    gpu: bool,
    asm_emulator: bool,
}

impl ZiskProver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binary: PathBuf,
        elf_path: PathBuf,
        aggregator_elf_path: Option<PathBuf>,
        proving_key: PathBuf,
        proving_key_plonk: PathBuf,
        work_dir_base: PathBuf,
        gpu: bool,
        asm_emulator: bool,
    ) -> Self {
        Self {
            binary,
            elf_path,
            aggregator_elf_path,
            proving_key,
            proving_key_plonk,
            work_dir_base,
            gpu,
            asm_emulator,
        }
    }

    fn aggregator_elf(&self) -> anyhow::Result<&Path> {
        self.aggregator_elf_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no aggregator ELF configured (--aggregator-elf)"))
    }

    /// One-time ROM setup for the STF guest ELF (`cargo-zisk
    /// program-setup`). Must run before the first `prove` for a given guest
    /// ELF; subsequent runs are cheap. Returns `Ok(false)` if cancelled.
    pub async fn ensure_program_setup(&self, cancel: &CancellationToken) -> anyhow::Result<bool> {
        let elf = self.elf_path.clone();
        self.program_setup(&elf, cancel).await
    }

    /// One-time ROM setup for the aggregator guest ELF (aggregated mode).
    pub async fn ensure_aggregator_program_setup(
        &self,
        cancel: &CancellationToken,
    ) -> anyhow::Result<bool> {
        let elf = self.aggregator_elf()?.to_path_buf();
        self.program_setup(&elf, cancel).await
    }

    async fn program_setup(&self, elf: &Path, cancel: &CancellationToken) -> anyhow::Result<bool> {
        let mut args = vec![
            "program-setup".to_string(),
            "-e".into(),
            p(elf),
            "-k".into(),
            p(&self.proving_key),
        ];
        if self.gpu {
            args.push("-g".into());
        }
        tracing::info!(elf = %elf.display(), "running program-setup");
        let start = Instant::now();
        let done = run_cancellable(&self.binary, &args, cancel).await?;
        if done {
            ZISK_PROVER_METRICS
                .program_setup_time
                .observe(start.elapsed());
            tracing::info!(
                elapsed_secs = start.elapsed().as_secs(),
                "program-setup complete"
            );
        }
        Ok(done)
    }

    /// Generate a per-batch ZiSK SNARK proof (PLONK wrap). Returns
    /// `Ok(None)` if cancelled.
    ///
    /// This is an async function — subprocesses are managed with `tokio::process`
    /// and cancellation uses `select!` against the token (instant response).
    pub async fn generate_proof(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Option<ZiskSnarkOutput>> {
        let start = Instant::now();
        let work_dir = self.work_dir_base.join(format!("batch_{batch_number}"));
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        tokio::fs::create_dir_all(&work_dir).await?;

        let result = async {
            let input_path = work_dir.join("input.bin");
            write_zisk_input(&input_path, zisk_bincode)?;
            let proof_path = work_dir.join("proof.bin");
            tracing::info!(batch_number, "proving (STARK + PLONK wrap) starting");
            if !self
                .run_prove(&self.elf_path, &input_path, &proof_path, true, cancel)
                .await?
            {
                return Ok(None);
            }
            parse_proof_file(&proof_path).map(Some)
        }
        .await;

        self.finish_run(&format!("batch {batch_number}"), &work_dir, start, result)
            .await
    }

    /// Generate a per-batch `vadcop_final` proof stream (no PLONK wrap) —
    /// the per-batch flow of AGGREGATED mode. The returned bytes are the
    /// exact `get_proof_bytes()` stream the aggregator guest verifies.
    /// Returns `Ok(None)` if cancelled.
    pub async fn generate_vadcop_proof(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let start = Instant::now();
        let work_dir = self.work_dir_base.join(format!("batch_{batch_number}"));
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        tokio::fs::create_dir_all(&work_dir).await?;

        let result = async {
            let input_path = work_dir.join("input.bin");
            write_zisk_input(&input_path, zisk_bincode)?;
            let proof_path = work_dir.join("proof.bin");
            tracing::info!(batch_number, "proving (STARK, vadcop_final kept) starting");
            if !self
                .run_prove(&self.elf_path, &input_path, &proof_path, false, cancel)
                .await?
            {
                return Ok(None);
            }
            vadcop_stream_from_proof_file(&proof_path).map(Some)
        }
        .await;

        self.finish_run(&format!("batch {batch_number}"), &work_dir, start, result)
            .await
    }

    /// Prove an aggregation range: verify the N per-batch `vadcop_final`
    /// streams in the aggregator guest and wrap the result in a PLONK SNARK
    /// for L1. `streams` must be in batch order; they are validated and
    /// framed by the input assembler before proving. Returns `Ok(None)` if
    /// cancelled.
    pub async fn generate_aggregated_proof(
        &self,
        streams: &[Vec<u8>],
        from_batch: u64,
        to_batch: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Option<ZiskSnarkOutput>> {
        let aggregator_elf = self.aggregator_elf()?.to_path_buf();
        let input = crate::aggregator_input::assemble(streams)?;

        let start = Instant::now();
        let work_dir = self
            .work_dir_base
            .join(format!("range_{from_batch}_{to_batch}"));
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        tokio::fs::create_dir_all(&work_dir).await?;

        let result = async {
            // The assembled input is already ziskos-framed (count frame +
            // one frame per stream) — written raw, unlike the per-batch
            // bincode which gets its single frame from `write_zisk_input`.
            let input_path = work_dir.join("input.bin");
            std::fs::write(&input_path, &input)?;
            let proof_path = work_dir.join("proof.bin");
            tracing::info!(
                from_batch,
                to_batch,
                proofs = streams.len(),
                "proving aggregation range (in-zkVM verification + PLONK wrap) starting"
            );
            if !self
                .run_prove(&aggregator_elf, &input_path, &proof_path, true, cancel)
                .await?
            {
                return Ok(None);
            }
            parse_proof_file(&proof_path).map(Some)
        }
        .await;

        self.finish_run(
            &format!("range {from_batch}..{to_batch}"),
            &work_dir,
            start,
            result,
        )
        .await
    }

    /// Shared `cargo-zisk prove` invocation (`-y` verifies the vadcop-final
    /// proof; with `plonk` the PLONK proving key and `--plonk` wrap are
    /// added). Returns `Ok(false)` if cancelled.
    async fn run_prove(
        &self,
        elf: &Path,
        input_path: &Path,
        proof_path: &Path,
        plonk: bool,
        cancel: &CancellationToken,
    ) -> anyhow::Result<bool> {
        let mut args = vec![
            "prove".to_string(),
            "-e".into(),
            p(elf),
            "-i".into(),
            p(input_path),
            "-k".into(),
            p(&self.proving_key),
        ];
        if plonk {
            args.push("-w".into());
            args.push(p(&self.proving_key_plonk));
            args.push("--plonk".into());
        }
        args.push("-y".into());
        args.push("-o".into());
        args.push(p(proof_path));
        if self.gpu {
            args.push("-g".into());
        }
        if !self.asm_emulator {
            // Standard emulator: slower witness-gen but no memlock
            // requirements (the ASM emulator needs a high memlock ulimit,
            // often unavailable in containers).
            args.push("-l".into());
        }
        let prove_start = Instant::now();
        if !run_cancellable(&self.binary, &args, cancel).await? {
            return Ok(false);
        }
        ZISK_PROVER_METRICS
            .prove_time
            .observe(prove_start.elapsed());
        anyhow::ensure!(proof_path.exists(), "proof file not generated");
        Ok(true)
    }

    /// Record metrics/logs for a finished proving run and clean up the work
    /// dir (kept on failure for debugging).
    async fn finish_run<T>(
        &self,
        label: &str,
        work_dir: &Path,
        start: Instant,
        result: anyhow::Result<Option<T>>,
    ) -> anyhow::Result<Option<T>> {
        let elapsed = start.elapsed();
        ZISK_PROVER_METRICS.proof_generation_time.observe(elapsed);
        let outcome = match &result {
            Ok(Some(_)) => crate::metrics::ProofOutcome::Success,
            Ok(None) => crate::metrics::ProofOutcome::Cancelled,
            Err(_) => crate::metrics::ProofOutcome::Failure,
        };
        ZISK_PROVER_METRICS.proofs[&outcome].inc();

        match &result {
            Ok(Some(_)) => {
                tracing::info!(label, elapsed_secs = elapsed.as_secs(), "proof generated");
                let _ = tokio::fs::remove_dir_all(&work_dir).await;
            }
            Ok(None) => {
                tracing::info!(label, "proof cancelled by shutdown");
                let _ = tokio::fs::remove_dir_all(&work_dir).await;
            }
            Err(e) => {
                tracing::error!(
                    label, elapsed_secs = elapsed.as_secs(),
                    path = %work_dir.display(), "proof failed: {e}"
                );
            }
        }

        result
    }
}

fn p(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn write_zisk_input(path: &Path, bincode: &[u8]) -> anyhow::Result<()> {
    let len = bincode.len() as u64;
    let mut buf = Vec::with_capacity(8 + bincode.len() + 8);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bincode);
    let padding = (8 - ((8 + bincode.len()) % 8)) % 8;
    buf.extend(std::iter::repeat_n(0u8, padding));
    std::fs::write(path, &buf)?;
    Ok(())
}

/// Run a subprocess, cancellable via token. Uses `tokio::process` — no polling.
///
/// stdout/stderr are inherited (not piped) to avoid blocking cargo-zisk's
/// 200+ threads on pipe buffer contention during proof generation.
async fn run_cancellable(
    binary: &Path,
    args: &[String],
    cancel: &CancellationToken,
) -> anyhow::Result<bool> {
    let mut child = tokio::process::Command::new(binary)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    tokio::select! {
        status = child.wait() => {
            let status = status?;
            if status.success() {
                Ok(true)
            } else {
                anyhow::bail!("{} failed with exit code: {:?}", binary.display(), status.code());
            }
        }
        _ = cancel.cancelled() => {
            tracing::info!("shutdown requested, killing subprocess");
            child.kill().await.ok();
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// v0.18.0 proof-file parsing.
//
// `cargo-zisk prove --plonk -o <file>` writes bincode-2 (standard config) of
// zisk-common's `Proof` struct. Rather than depending on zisk-common (which
// pulls in the whole proofman stack), we mirror the exact struct shapes and
// deserialize with serde + bincode 2. Shapes must match
// zisk@v0.18.0 `common/src/proof.rs` field-for-field.
// ---------------------------------------------------------------------------

#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
struct ZiskProofFile {
    body: ZiskProofBody,
    publics: ZiskPublicValues,
    program_vk: ZiskProgramVk,
}

#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
enum ZiskProofBody {
    #[allow(dead_code)]
    Vadcop {
        proof: Vec<u64>,
        zisk_vk: Vec<u64>,
        minimal: bool,
    },
    Plonk {
        proof_bytes: Vec<u8>,
        plonk_vk: Box<ZiskPlonkVkBlob>,
    },
}

#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
struct ZiskPlonkVkBlob {
    vadcop_vk: Vec<u64>,
    #[allow(dead_code)]
    plonk_vkey: ZiskPlonkVkey,
}

/// snarkJS Plonk verification key (decoded only to advance the deserializer).
#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ZiskPlonkVkey {
    protocol: String,
    curve: String,
    n_public: u32,
    power: u32,
    k1: String,
    k2: String,
    qm: [String; 3],
    ql: [String; 3],
    qr: [String; 3],
    qo: [String; 3],
    qc: [String; 3],
    s1: [String; 3],
    s2: [String; 3],
    s3: [String; 3],
    x_2: [[String; 2]; 3],
    w: String,
}

/// Mirror of `PublicValues { data, #[serde(skip)] ptr }` — skipped fields are
/// absent from the bincode stream, so only `data` is mirrored.
#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
struct ZiskPublicValues {
    data: Vec<u8>,
}

#[cfg_attr(test, derive(serde::Serialize))]
#[derive(serde::Deserialize)]
struct ZiskProgramVk {
    vk: Vec<u64>,
}

/// Extract `(proof, public_values)` in the server's wire format:
/// - proof: the 768-byte BN254 PLONK SNARK.
/// - public_values (320 bytes): `program_vk (32B, u64 BE) ‖ publics.data
///   (256B) ‖ vadcop_final_vk (32B, u64 BE)` — the exact preimage of the
///   circuit's single public signal (`sha256(...) % r`), matching
///   zisk-common's `PublicValues::bytes_solidity` and the on-chain
///   `ZiskVerifier` digest reconstruction.
pub fn parse_proof_file(path: &Path) -> anyhow::Result<ZiskSnarkOutput> {
    let data = std::fs::read(path)?;
    let (proof_file, consumed): (ZiskProofFile, usize) =
        bincode::serde::decode_from_slice(&data, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("failed to decode proof file: {e}"))?;
    anyhow::ensure!(
        consumed == data.len(),
        "trailing bytes in proof file: decoded {consumed} of {}",
        data.len()
    );

    let ZiskProofBody::Plonk {
        proof_bytes,
        plonk_vk,
    } = proof_file.body
    else {
        anyhow::bail!("proof file contains a Vadcop proof, expected Plonk (missing --plonk?)");
    };
    anyhow::ensure!(
        proof_bytes.len() == ZISK_SNARK_PROOF_BYTES,
        "proof length {} != {ZISK_SNARK_PROOF_BYTES}",
        proof_bytes.len()
    );
    anyhow::ensure!(
        proof_file.program_vk.vk.len() == PROGRAM_VK_LEN,
        "program VK has {} words, expected {PROGRAM_VK_LEN}",
        proof_file.program_vk.vk.len()
    );
    anyhow::ensure!(
        plonk_vk.vadcop_vk.len() == PROGRAM_VK_LEN,
        "vadcop VK has {} words, expected {PROGRAM_VK_LEN}",
        plonk_vk.vadcop_vk.len()
    );

    let mut public_values = Vec::with_capacity(ZISK_PUBLIC_VALUES_BYTES);
    for word in &proof_file.program_vk.vk {
        public_values.extend_from_slice(&word.to_be_bytes());
    }
    public_values.extend_from_slice(&proof_file.publics.data);
    for word in &plonk_vk.vadcop_vk {
        public_values.extend_from_slice(&word.to_be_bytes());
    }
    anyhow::ensure!(
        public_values.len() == ZISK_PUBLIC_VALUES_BYTES,
        "public values length {} != {ZISK_PUBLIC_VALUES_BYTES} (publics data {} bytes)",
        public_values.len(),
        proof_file.publics.data.len()
    );

    Ok(ZiskSnarkOutput {
        proof: proof_bytes,
        public_values,
    })
}

/// Extract the serialized `vadcop_final` proof stream — the exact byte
/// layout of `zisk_common::Proof::get_proof_bytes()`, which is what the
/// aggregator guest verifies in-zkVM — from a `cargo-zisk prove` output
/// file with a **Vadcop** body (a run WITHOUT `--plonk`; with `--plonk`
/// the file holds only the BN254 wrap and the vadcop_final proof is gone).
///
/// Stream layout (u64 LE words):
/// `[minimal=0][n_publics=68][program_vk(4)][publics(64)][body][vadcop_vk(4)]`.
pub fn vadcop_stream_from_proof_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    use zksync_os_zisk_guest_aggregator as agg;

    let data = std::fs::read(path)?;
    let (proof_file, consumed): (ZiskProofFile, usize) =
        bincode::serde::decode_from_slice(&data, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("failed to decode proof file: {e}"))?;
    anyhow::ensure!(
        consumed == data.len(),
        "trailing bytes in proof file: decoded {consumed} of {}",
        data.len()
    );

    let ZiskProofBody::Vadcop {
        proof,
        zisk_vk,
        minimal,
    } = proof_file.body
    else {
        anyhow::bail!(
            "proof file contains a Plonk proof, expected a vadcop_final body \
             (run cargo-zisk prove WITHOUT --plonk to keep the vadcop_final proof)"
        );
    };
    anyhow::ensure!(
        !minimal,
        "proof file contains a minimal vadcop_final proof; the aggregator \
         accepts only non-minimal proofs (Poseidon2-16 precompile path)"
    );
    anyhow::ensure!(
        proof.len() == agg::VADCOP_FINAL_BODY_WORDS,
        "vadcop_final body has {} words, expected {} — pil2-proofman pin mismatch?",
        proof.len(),
        agg::VADCOP_FINAL_BODY_WORDS
    );
    anyhow::ensure!(
        proof_file.program_vk.vk.len() == PROGRAM_VK_LEN,
        "program VK has {} words, expected {PROGRAM_VK_LEN}",
        proof_file.program_vk.vk.len()
    );
    anyhow::ensure!(
        zisk_vk.len() == PROGRAM_VK_LEN,
        "vadcop VK has {} words, expected {PROGRAM_VK_LEN}",
        zisk_vk.len()
    );
    anyhow::ensure!(
        proof_file.publics.data.len() == agg::PUBLICS_WORDS * 4,
        "publics region has {} bytes, expected {}",
        proof_file.publics.data.len(),
        agg::PUBLICS_WORDS * 4
    );

    let mut words: Vec<u64> = Vec::with_capacity(agg::PROOF_STREAM_WORDS);
    words.push(0); // non-minimal
    words.push((PROGRAM_VK_LEN + agg::PUBLICS_WORDS) as u64); // n_publics = 68
    words.extend_from_slice(&proof_file.program_vk.vk);
    // Each public is a u32 stored LE in `data`, widened to a u64 word
    // (mirrors zisk-common's `PublicValues::public_u64`).
    words.extend(
        proof_file
            .publics
            .data
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()) as u64),
    );
    words.extend_from_slice(&proof);
    words.extend_from_slice(&zisk_vk);
    debug_assert_eq!(words.len(), agg::PROOF_STREAM_WORDS);

    let mut bytes = Vec::with_capacity(words.len() * 8);
    for w in &words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe() -> String {
        "12539294771426046350380723674544937632432364684958450364901655716930754226695".into()
    }

    fn sample_vkey() -> ZiskPlonkVkey {
        ZiskPlonkVkey {
            protocol: "plonk".into(),
            curve: "bn128".into(),
            n_public: 1,
            power: 24,
            k1: "2".into(),
            k2: "3".into(),
            qm: [fe(), fe(), "1".into()],
            ql: [fe(), fe(), "1".into()],
            qr: [fe(), fe(), "1".into()],
            qo: [fe(), fe(), "1".into()],
            qc: [fe(), fe(), "1".into()],
            s1: [fe(), fe(), "1".into()],
            s2: [fe(), fe(), "1".into()],
            s3: [fe(), fe(), "1".into()],
            x_2: [[fe(), fe()], [fe(), fe()], [fe(), fe()]],
            w: fe(),
        }
    }

    #[test]
    fn parse_proof_file_roundtrip() {
        let program_vk = vec![0x1111_2222_3333_4444u64; PROGRAM_VK_LEN];
        let vadcop_vk = vec![0xaaaa_bbbb_cccc_ddddu64; PROGRAM_VK_LEN];
        let publics_data = vec![0x42u8; ZISK_PUBLIC_VALUES_BYTES - 2 * PROGRAM_VK_LEN * 8];
        let proof = ZiskProofFile {
            body: ZiskProofBody::Plonk {
                proof_bytes: vec![7u8; ZISK_SNARK_PROOF_BYTES],
                plonk_vk: Box::new(ZiskPlonkVkBlob {
                    vadcop_vk: vadcop_vk.clone(),
                    plonk_vkey: sample_vkey(),
                }),
            },
            publics: ZiskPublicValues {
                data: publics_data.clone(),
            },
            program_vk: ZiskProgramVk {
                vk: program_vk.clone(),
            },
        };

        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let dir = std::env::temp_dir().join(format!("zisk_prover_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proof.bin");
        std::fs::write(&path, &bytes).unwrap();

        let out = parse_proof_file(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(out.proof, vec![7u8; ZISK_SNARK_PROOF_BYTES]);
        assert_eq!(out.public_values.len(), ZISK_PUBLIC_VALUES_BYTES);
        // program VK words big-endian first, then publics data, then vadcop VK.
        assert_eq!(
            &out.public_values[..8],
            0x1111_2222_3333_4444u64.to_be_bytes().as_slice()
        );
        assert_eq!(out.public_values[32..288], publics_data[..]);
        assert_eq!(
            &out.public_values[288..296],
            0xaaaa_bbbb_cccc_ddddu64.to_be_bytes().as_slice()
        );
    }

    #[test]
    fn vadcop_stream_extraction_roundtrip() {
        use zksync_os_zisk_guest_aggregator as agg;

        let program_vk = vec![1u64, 2, 3, 4];
        let zisk_vk = vec![5u64, 6, 7, 8];
        let body = vec![7u64; agg::VADCOP_FINAL_BODY_WORDS];
        // 64 u32 publics, LE-packed: first 8 words carry 0x11111111.
        let mut publics_data = vec![0u8; agg::PUBLICS_WORDS * 4];
        publics_data[..32].copy_from_slice(&[0x11u8; 32]);

        let proof = ZiskProofFile {
            body: ZiskProofBody::Vadcop {
                proof: body.clone(),
                zisk_vk: zisk_vk.clone(),
                minimal: false,
            },
            publics: ZiskPublicValues { data: publics_data },
            program_vk: ZiskProgramVk {
                vk: program_vk.clone(),
            },
        };
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let dir = std::env::temp_dir().join(format!("zisk_agg_stream_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vadcop_final_proof.bin");
        std::fs::write(&path, &bytes).unwrap();

        let stream = vadcop_stream_from_proof_file(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(stream.len(), agg::PROOF_STREAM_BYTES);
        // Validate with the guest's own parser: the two implementations
        // must agree on the layout by construction.
        let words = agg::words_from_bytes(&stream).unwrap();
        let frame = agg::ProofFrame::parse(words).unwrap();
        assert_eq!(frame.program_vk(), program_vk.as_slice());
        assert_eq!(frame.vadcop_vk(), zisk_vk.as_slice());
        assert_eq!(frame.commitment(), [0x11u8; 32]);
        let body_start = agg::HEADER_WORDS + agg::PROGRAM_VK_WORDS + agg::PUBLICS_WORDS;
        assert_eq!(
            &words[body_start..body_start + agg::VADCOP_FINAL_BODY_WORDS],
            body.as_slice()
        );
    }

    #[test]
    fn vadcop_stream_rejects_plonk_and_minimal() {
        use zksync_os_zisk_guest_aggregator as agg;

        let dir = std::env::temp_dir().join(format!("zisk_agg_reject_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Plonk body — the file the daemon submits to the server.
        let plonk = ZiskProofFile {
            body: ZiskProofBody::Plonk {
                proof_bytes: vec![7u8; ZISK_SNARK_PROOF_BYTES],
                plonk_vk: Box::new(ZiskPlonkVkBlob {
                    vadcop_vk: vec![0; 4],
                    plonk_vkey: sample_vkey(),
                }),
            },
            publics: ZiskPublicValues { data: vec![0; 256] },
            program_vk: ZiskProgramVk { vk: vec![0; 4] },
        };
        let path = dir.join("plonk.bin");
        std::fs::write(
            &path,
            bincode::serde::encode_to_vec(&plonk, bincode::config::standard()).unwrap(),
        )
        .unwrap();
        let err = vadcop_stream_from_proof_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Plonk"), "unexpected error: {err}");

        // Minimal vadcop body — Poseidon2-8, no precompile: refused.
        let minimal = ZiskProofFile {
            body: ZiskProofBody::Vadcop {
                proof: vec![7u64; agg::VADCOP_FINAL_BODY_WORDS],
                zisk_vk: vec![0; 4],
                minimal: true,
            },
            publics: ZiskPublicValues { data: vec![0; 256] },
            program_vk: ZiskProgramVk { vk: vec![0; 4] },
        };
        let path = dir.join("minimal.bin");
        std::fs::write(
            &path,
            bincode::serde::encode_to_vec(&minimal, bincode::config::standard()).unwrap(),
        )
        .unwrap();
        let err = vadcop_stream_from_proof_file(&path)
            .unwrap_err()
            .to_string();
        std::fs::remove_dir_all(&dir).ok();
        assert!(err.contains("minimal"), "unexpected error: {err}");
    }

    /// The guest-side body-size constant must match the pinned
    /// pil2-proofman verifier exactly — this is the only place the pin is
    /// checked mechanically (see `VADCOP_FINAL_BODY_WORDS` docs).
    #[test]
    fn vadcop_body_words_matches_pinned_verifier() {
        assert_eq!(
            zksync_os_zisk_guest_aggregator::VADCOP_FINAL_BODY_WORDS * 8,
            proofman_verifier::expected_vadcop_final_proof_bytes(),
        );
    }

    #[test]
    fn parse_rejects_vadcop_body() {
        let proof = ZiskProofFile {
            body: ZiskProofBody::Vadcop {
                proof: vec![1, 2, 3],
                zisk_vk: vec![0; 4],
                minimal: false,
            },
            publics: ZiskPublicValues { data: vec![] },
            program_vk: ZiskProgramVk { vk: vec![0; 4] },
        };
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let dir =
            std::env::temp_dir().join(format!("zisk_prover_test_vadcop_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proof.bin");
        std::fs::write(&path, &bytes).unwrap();
        let err = parse_proof_file(&path).unwrap_err().to_string();
        std::fs::remove_dir_all(&dir).ok();
        assert!(err.contains("Vadcop"), "unexpected error: {err}");
    }
}
