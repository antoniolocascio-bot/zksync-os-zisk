//! ZiSK proof generation via `cargo-zisk` subprocesses (ZiSK v0.18.0).
//!
//! v0.18.0 replaces the old two-step flow (`prove --aggregation` +
//! `prove-snark`) with a single integrated `prove --plonk` invocation that
//! takes the batch all the way to a BN254 PLONK SNARK. A one-time
//! `program-setup` per guest ELF generates the ROM setup the prover needs.
//!
//! Uses `tokio::process` so subprocess waits can be cancelled instantly
//! via `CancellationToken` — no busy-polling.

use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::metrics::ZISK_PROVER_METRICS;

const ZISK_SNARK_PROOF_BYTES: usize = 768;
const ZISK_PUBLIC_VALUES_BYTES: usize = 256;
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
    proving_key: PathBuf,
    proving_key_plonk: PathBuf,
    work_dir_base: PathBuf,
    gpu: bool,
    asm_emulator: bool,
}

impl ZiskProver {
    pub fn new(
        binary: PathBuf,
        elf_path: PathBuf,
        proving_key: PathBuf,
        proving_key_plonk: PathBuf,
        work_dir_base: PathBuf,
        gpu: bool,
        asm_emulator: bool,
    ) -> Self {
        Self { binary, elf_path, proving_key, proving_key_plonk, work_dir_base, gpu, asm_emulator }
    }

    /// One-time per-ELF ROM setup (`cargo-zisk program-setup`). Must run
    /// before the first `prove` for a given guest ELF; subsequent runs are
    /// cheap. Returns `Ok(false)` if cancelled.
    pub async fn ensure_program_setup(&self, cancel: &CancellationToken) -> anyhow::Result<bool> {
        let mut args = vec![
            "program-setup".to_string(),
            "-e".into(), p(&self.elf_path),
            "-k".into(), p(&self.proving_key),
        ];
        if self.gpu {
            args.push("-g".into());
        }
        tracing::info!(elf = %self.elf_path.display(), "running program-setup");
        let start = Instant::now();
        let done = run_cancellable(&self.binary, &args, cancel).await?;
        if done {
            ZISK_PROVER_METRICS.program_setup_time.observe(start.elapsed());
            tracing::info!(elapsed_secs = start.elapsed().as_secs(), "program-setup complete");
        }
        Ok(done)
    }

    /// Generate a ZiSK SNARK proof. Returns `Ok(None)` if cancelled.
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

        let result = self.run_pipeline(zisk_bincode, batch_number, &work_dir, cancel).await;

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
                tracing::info!(batch_number, elapsed_secs = elapsed.as_secs(), "proof generated");
                let _ = tokio::fs::remove_dir_all(&work_dir).await;
            }
            Ok(None) => {
                tracing::info!(batch_number, "proof cancelled by shutdown");
                let _ = tokio::fs::remove_dir_all(&work_dir).await;
            }
            Err(e) => {
                tracing::error!(
                    batch_number, elapsed_secs = elapsed.as_secs(),
                    path = %work_dir.display(), "proof failed: {e}"
                );
            }
        }

        result
    }

    async fn run_pipeline(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
        work_dir: &Path,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Option<ZiskSnarkOutput>> {
        let input_path = work_dir.join("input.bin");
        write_zisk_input(&input_path, zisk_bincode)?;

        // Integrated STARK aggregation + PLONK SNARK wrap (`-y` verifies the
        // vadcop-final proof before wrapping).
        let proof_path = work_dir.join("proof.bin");
        let mut args = vec![
            "prove".to_string(),
            "-e".into(), p(&self.elf_path),
            "-i".into(), p(&input_path),
            "-k".into(), p(&self.proving_key),
            "-w".into(), p(&self.proving_key_plonk),
            "--plonk".into(),
            "-y".into(),
            "-o".into(), p(&proof_path),
        ];
        if self.gpu {
            args.push("-g".into());
        }
        if !self.asm_emulator {
            // Standard emulator: slower witness-gen but no memlock
            // requirements (the ASM emulator needs a high memlock ulimit,
            // often unavailable in containers).
            args.push("-l".into());
        }
        tracing::info!(batch_number, "proving (STARK + PLONK wrap) starting");
        let prove_start = Instant::now();
        if !run_cancellable(&self.binary, &args, cancel).await? {
            return Ok(None);
        }
        ZISK_PROVER_METRICS.prove_time.observe(prove_start.elapsed());

        anyhow::ensure!(proof_path.exists(), "proof file not generated");
        parse_proof_file(&proof_path).map(Some)
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
    buf.extend(std::iter::repeat(0u8).take(padding));
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
    Vadcop { proof: Vec<u64>, zisk_vk: Vec<u64>, minimal: bool },
    Plonk { proof_bytes: Vec<u8>, plonk_vk: Box<ZiskPlonkVkBlob> },
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
/// - public_values (256 bytes): `program_vk (32B, u64 BE) ‖ publics.data
///   (192B) ‖ vadcop_final_vk (32B, u64 BE)` — the exact preimage of the
///   circuit's single public signal (`sha256(...) % r`), matching
///   zisk-common's `PublicValues::bytes_solidity` and the on-chain
///   `ZiskVerifier` digest reconstruction.
fn parse_proof_file(path: &Path) -> anyhow::Result<ZiskSnarkOutput> {
    let data = std::fs::read(path)?;
    let (proof_file, consumed): (ZiskProofFile, usize) =
        bincode::serde::decode_from_slice(&data, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("failed to decode proof file: {e}"))?;
    anyhow::ensure!(
        consumed == data.len(),
        "trailing bytes in proof file: decoded {consumed} of {}",
        data.len()
    );

    let ZiskProofBody::Plonk { proof_bytes, plonk_vk } = proof_file.body else {
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

    Ok(ZiskSnarkOutput { proof: proof_bytes, public_values })
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
            publics: ZiskPublicValues { data: publics_data.clone() },
            program_vk: ZiskProgramVk { vk: program_vk.clone() },
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
        assert_eq!(&out.public_values[..8], 0x1111_2222_3333_4444u64.to_be_bytes().as_slice());
        assert_eq!(out.public_values[32..224], publics_data[..]);
        assert_eq!(&out.public_values[224..232], 0xaaaa_bbbb_cccc_ddddu64.to_be_bytes().as_slice());
    }

    #[test]
    fn parse_rejects_vadcop_body() {
        let proof = ZiskProofFile {
            body: ZiskProofBody::Vadcop { proof: vec![1, 2, 3], zisk_vk: vec![0; 4], minimal: false },
            publics: ZiskPublicValues { data: vec![] },
            program_vk: ZiskProgramVk { vk: vec![0; 4] },
        };
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let dir = std::env::temp_dir().join(format!("zisk_prover_test_vadcop_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proof.bin");
        std::fs::write(&path, &bytes).unwrap();
        let err = parse_proof_file(&path).unwrap_err().to_string();
        std::fs::remove_dir_all(&dir).ok();
        assert!(err.contains("Vadcop"), "unexpected error: {err}");
    }
}
