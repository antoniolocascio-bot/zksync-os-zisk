//! Pure parsing / validation / commitment logic for the ZiSK proof
//! aggregator guest.
//!
//! Everything in this library is host-testable: it depends only on `core`
//! plus a keccak backend (the ZiSK-accelerated `alloy-primitives` native
//! keccak inside the zkVM, `tiny-keccak` on the host — same function, so
//! host tests exercise the exact logic the guest runs). The zkVM binary
//! (`src/main.rs`) is a thin shell that wires these functions to `ziskos`
//! I/O and in-guest proof verification; the host-side input assembler
//! (`prover/src/aggregator_input.rs`) reuses this parser to validate the
//! streams it frames, so assembler and guest can never disagree on layout.
//!
//! # Serialized proof stream (u64 LE words)
//!
//! The unit of input is the byte stream `cargo-zisk` clients obtain from
//! `zisk_common::Proof::get_proof_bytes()` for a **non-minimal
//! `vadcop_final`** proof (ZiSK v0.18.0):
//!
//! ```text
//! [minimal(1)][n_publics=68(1)][program_vk(4)][publics(64)]
//! [proof body(41_947)][vadcop_vk(4)]
//! ```
//!
//! `publics[0..8]` carry the STF guest's batch-commitment u32 words (one
//! u32 per u64 word, packed little-endian by `ziskos::io::commit_slice`).
//! Only non-minimal proofs are accepted: the minimal/compressed variant
//! hashes with Poseidon2-8, which has no ZiSK precompile and would run the
//! permutation in software.
//!
//! # Committed output
//!
//! PROVISIONAL layout — the L1 binding scheme is decided with tasks 7.x/8;
//! change it here (and in [`Aggregator::finalize`]) only, everything else
//! is layout-agnostic. Both inner VKs are prover-supplied input, so they
//! MUST be part of the committed output for the proof to bind them:
//!
//! ```text
//! keccak256(
//!     program_vk words as 8-byte LE each (32 bytes)
//!  ‖  vadcop_vk  words as 8-byte LE each (32 bytes)
//!  ‖  rolling
//! )
//! where rolling = fold(keccak256, [0u8; 32], commitment_1 .. commitment_N)
//! and commitment_i = publics[0..8] of proof i as u32-LE bytes (32 bytes),
//! matching the STF guest's `commit_slice` packing.
//! ```

#![cfg_attr(not(test), no_std)]

/// Words preceding the publics in a serialized proof: `[minimal][n_publics]`.
pub const HEADER_WORDS: usize = 2;
/// u64 words in the guest-ELF ROM root (program VK).
pub const PROGRAM_VK_WORDS: usize = 4;
/// u64 words in the publics region (`zisk_verifier::ZISK_PUBLICS`).
pub const PUBLICS_WORDS: usize = 64;
/// u64 words in the vadcop-final verification key appended to the stream.
pub const VADCOP_VK_WORDS: usize = 4;
/// Publics words carrying the STF guest's batch commitment.
pub const COMMITMENT_WORDS: usize = 8;
/// Expected `n_publics` header word: program VK + publics.
pub const EXPECTED_N_PUBLICS: u64 = (PROGRAM_VK_WORDS + PUBLICS_WORDS) as u64;

/// u64 words in a non-minimal `vadcop_final` proof body under the pinned
/// pil2-proofman v0.18.0 recursive setup
/// (`proofman_verifier::expected_vadcop_final_proof_bytes() / 8`).
///
/// Part of the proof-format pin: it changes only with a
/// pil2-proofman upgrade, which rotates every VK anyway. A host test in
/// `prover/` (`vadcop_body_words_matches_pinned_verifier`) asserts this
/// constant against the real `proofman-verifier` crate at the same tag.
pub const VADCOP_FINAL_BODY_WORDS: usize = 41_947;

/// Total u64 words in a serialized non-minimal proof stream.
pub const PROOF_STREAM_WORDS: usize =
    HEADER_WORDS + PROGRAM_VK_WORDS + PUBLICS_WORDS + VADCOP_FINAL_BODY_WORDS + VADCOP_VK_WORDS;
/// Total bytes in a serialized non-minimal proof stream.
pub const PROOF_STREAM_BYTES: usize = PROOF_STREAM_WORDS * 8;

/// Bytes committed by the aggregator guest (a single keccak digest).
pub const OUTPUT_BYTES: usize = 32;

/// Validation errors. Every variant is a hard input error — the guest
/// panics on all of them (an aggregation input is assembled by our own
/// tooling; anything malformed is a bug, not an expected condition).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggError {
    /// Frame bytes are not 8-byte aligned or not a multiple of 8 long.
    Misaligned,
    /// The count frame is not exactly 8 bytes.
    BadCountFrame { len: usize },
    /// The proof count is zero (or an aggregation was finalized empty).
    NoProofs,
    /// A proof frame is not exactly [`PROOF_STREAM_WORDS`] long.
    WrongLength { words: usize },
    /// The `minimal` flag word is not 0 — minimal proofs are not accepted.
    MinimalProof { flag: u64 },
    /// The `n_publics` header word is not [`EXPECTED_N_PUBLICS`].
    BadPublicsCount { got: u64 },
    /// A proof's program VK differs from the first proof's.
    ProgramVkMismatch,
    /// A proof's vadcop VK differs from the first proof's.
    VadcopVkMismatch,
}

impl core::fmt::Display for AggError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AggError::Misaligned => write!(f, "input frame not u64-aligned"),
            AggError::BadCountFrame { len } => {
                write!(f, "count frame must be 8 bytes, got {len}")
            }
            AggError::NoProofs => write!(f, "at least one proof required"),
            AggError::WrongLength { words } => write!(
                f,
                "proof stream must be exactly {PROOF_STREAM_WORDS} words, got {words}"
            ),
            AggError::MinimalProof { flag } => {
                write!(f, "minimal proofs are not accepted (flag word {flag})")
            }
            AggError::BadPublicsCount { got } => {
                write!(f, "n_publics must be {EXPECTED_N_PUBLICS}, got {got}")
            }
            AggError::ProgramVkMismatch => write!(f, "program VK mismatch"),
            AggError::VadcopVkMismatch => write!(f, "vadcop VK mismatch"),
        }
    }
}

/// Parse the count frame (frame 0): a single u64 LE proof count, N >= 1.
pub fn parse_count_frame(bytes: &[u8]) -> Result<usize, AggError> {
    let words: [u8; 8] = bytes
        .try_into()
        .map_err(|_| AggError::BadCountFrame { len: bytes.len() })?;
    let n = u64::from_le_bytes(words) as usize;
    if n == 0 {
        return Err(AggError::NoProofs);
    }
    Ok(n)
}

/// Reinterpret frame bytes as u64 words (zero-copy).
pub fn words_from_bytes(bytes: &[u8]) -> Result<&[u64], AggError> {
    // SAFETY: any bit pattern is a valid u64; alignment and exact length
    // are enforced via the prefix/suffix emptiness check below.
    let (prefix, words, suffix) = unsafe { bytes.align_to::<u64>() };
    if !prefix.is_empty() || !suffix.is_empty() {
        return Err(AggError::Misaligned);
    }
    Ok(words)
}

/// A validated, non-minimal `vadcop_final` proof stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofFrame<'a> {
    words: &'a [u64],
}

impl<'a> ProofFrame<'a> {
    /// Validate the stream shape: exact length, non-minimal flag, publics
    /// count. Cryptographic verification is the caller's job
    /// (`ziskos::zisklib::verify_zisk_proof(frame.words())` in the guest).
    pub fn parse(words: &'a [u64]) -> Result<Self, AggError> {
        if words.len() != PROOF_STREAM_WORDS {
            return Err(AggError::WrongLength { words: words.len() });
        }
        if words[0] != 0 {
            return Err(AggError::MinimalProof { flag: words[0] });
        }
        if words[1] != EXPECTED_N_PUBLICS {
            return Err(AggError::BadPublicsCount { got: words[1] });
        }
        Ok(Self { words })
    }

    /// The full stream, exactly what `verify_zisk_proof` consumes
    /// (`[minimal][n_publics][program_vk][publics][body][vadcop_vk]`).
    pub fn words(&self) -> &'a [u64] {
        self.words
    }

    /// The inner guest's program VK (ROM root), 4 words.
    pub fn program_vk(&self) -> &'a [u64] {
        &self.words[HEADER_WORDS..HEADER_WORDS + PROGRAM_VK_WORDS]
    }

    /// The recursive-setup (vadcop-final) VK trailing the stream, 4 words.
    pub fn vadcop_vk(&self) -> &'a [u64] {
        &self.words[self.words.len() - VADCOP_VK_WORDS..]
    }

    /// The 64 publics words (each carries a u32 payload).
    pub fn publics(&self) -> &'a [u64] {
        let start = HEADER_WORDS + PROGRAM_VK_WORDS;
        &self.words[start..start + PUBLICS_WORDS]
    }

    /// The STF guest's 32-byte batch commitment: publics words 0..8, one
    /// u32 per word, packed LE exactly as the STF guest committed them
    /// (the `as u32` truncation matches `PublicValues::new_from_u64`).
    pub fn commitment(&self) -> [u8; 32] {
        let mut out = [0u8; COMMITMENT_WORDS * 4];
        for (w, chunk) in self.publics()[..COMMITMENT_WORDS]
            .iter()
            .zip(out.chunks_exact_mut(4))
        {
            chunk.copy_from_slice(&(*w as u32).to_le_bytes());
        }
        out
    }
}

/// Accumulates the aggregation state over a sequence of parsed frames:
/// enforces that all proofs share one (program VK, vadcop VK) pair and
/// chains their batch commitments into a rolling keccak.
pub struct Aggregator {
    vks: Option<([u64; PROGRAM_VK_WORDS], [u64; VADCOP_VK_WORDS])>,
    rolling: [u8; 32],
}

impl Aggregator {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            vks: None,
            rolling: [0u8; 32],
        }
    }

    /// Fold one frame in. All aggregated proofs must come from one guest
    /// and one recursive setup; the shared values are bound into the
    /// committed output.
    pub fn ingest(&mut self, frame: &ProofFrame<'_>) -> Result<(), AggError> {
        match &self.vks {
            None => {
                let mut pvk = [0u64; PROGRAM_VK_WORDS];
                let mut vvk = [0u64; VADCOP_VK_WORDS];
                pvk.copy_from_slice(frame.program_vk());
                vvk.copy_from_slice(frame.vadcop_vk());
                self.vks = Some((pvk, vvk));
            }
            Some((pvk, vvk)) => {
                if frame.program_vk() != pvk {
                    return Err(AggError::ProgramVkMismatch);
                }
                if frame.vadcop_vk() != vvk {
                    return Err(AggError::VadcopVkMismatch);
                }
            }
        }

        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&self.rolling);
        preimage[32..].copy_from_slice(&frame.commitment());
        self.rolling = keccak256(&preimage);
        Ok(())
    }

    /// The committed output (see the crate docs for the PROVISIONAL
    /// layout): `keccak256(program_vk LE ‖ vadcop_vk LE ‖ rolling)`.
    pub fn finalize(self) -> Result<[u8; OUTPUT_BYTES], AggError> {
        let (program_vk, vadcop_vk) = self.vks.ok_or(AggError::NoProofs)?;
        let mut binding = [0u8; 96];
        for (w, chunk) in program_vk.iter().zip(binding[..32].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        for (w, chunk) in vadcop_vk.iter().zip(binding[32..64].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        binding[64..].copy_from_slice(&self.rolling);
        Ok(keccak256(&binding))
    }
}

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
#[inline]
fn keccak256(data: &[u8]) -> [u8; 32] {
    alloy_primitives::keccak256(data).0
}

#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::Hasher;
    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROGRAM_VK: [u64; 4] = [1, 2, 3, 4];
    const VADCOP_VK: [u64; 4] = [5, 6, 7, 8];

    /// A well-shaped synthetic stream: exact v0.18.0 sizes, non-minimal,
    /// commitment words carrying `commitment_word` u32 payloads. The body
    /// is deterministic filler — cryptographically invalid, structurally
    /// exact.
    fn synth_stream(program_vk: [u64; 4], vadcop_vk: [u64; 4], commitment_word: u32) -> Vec<u64> {
        let mut words = Vec::with_capacity(PROOF_STREAM_WORDS);
        words.push(0); // non-minimal
        words.push(EXPECTED_N_PUBLICS);
        words.extend_from_slice(&program_vk);
        let mut publics = [0u64; PUBLICS_WORDS];
        for p in publics.iter_mut().take(COMMITMENT_WORDS) {
            *p = commitment_word as u64;
        }
        words.extend_from_slice(&publics);
        words.extend((0..VADCOP_FINAL_BODY_WORDS).map(|i| (i as u64) % (1 << 31)));
        words.extend_from_slice(&vadcop_vk);
        assert_eq!(words.len(), PROOF_STREAM_WORDS);
        words
    }

    #[test]
    fn count_frame_roundtrip() {
        assert_eq!(parse_count_frame(&3u64.to_le_bytes()), Ok(3));
        assert_eq!(
            parse_count_frame(&[0u8; 4]),
            Err(AggError::BadCountFrame { len: 4 })
        );
        assert_eq!(
            parse_count_frame(&[0u8; 9]),
            Err(AggError::BadCountFrame { len: 9 })
        );
        assert_eq!(parse_count_frame(&0u64.to_le_bytes()), Err(AggError::NoProofs));
    }

    #[test]
    fn words_from_bytes_enforces_shape() {
        let buf = [0u64; 4];
        let bytes: &[u8] =
            unsafe { core::slice::from_raw_parts(buf.as_ptr().cast(), 32) };
        assert_eq!(words_from_bytes(bytes).unwrap().len(), 4);
        // Not a multiple of 8.
        assert_eq!(words_from_bytes(&bytes[..15]), Err(AggError::Misaligned));
        // 8-byte length but off-alignment start.
        assert_eq!(words_from_bytes(&bytes[1..9]), Err(AggError::Misaligned));
    }

    #[test]
    fn parse_accepts_well_shaped_stream() {
        let words = synth_stream(PROGRAM_VK, VADCOP_VK, 0x1111_1111);
        let frame = ProofFrame::parse(&words).expect("well-shaped stream parses");
        assert_eq!(frame.program_vk(), &PROGRAM_VK);
        assert_eq!(frame.vadcop_vk(), &VADCOP_VK);
        assert_eq!(frame.publics().len(), PUBLICS_WORDS);
        assert_eq!(frame.commitment(), [0x11u8; 32]);
        assert_eq!(frame.words().len(), PROOF_STREAM_WORDS);
    }

    #[test]
    fn parse_rejects_minimal_flag() {
        let mut words = synth_stream(PROGRAM_VK, VADCOP_VK, 1);
        words[0] = 1;
        assert_eq!(
            ProofFrame::parse(&words),
            Err(AggError::MinimalProof { flag: 1 })
        );
    }

    #[test]
    fn parse_rejects_bad_publics_count() {
        let mut words = synth_stream(PROGRAM_VK, VADCOP_VK, 1);
        words[1] = 67;
        assert_eq!(
            ProofFrame::parse(&words),
            Err(AggError::BadPublicsCount { got: 67 })
        );
    }

    #[test]
    fn parse_rejects_wrong_lengths() {
        let words = synth_stream(PROGRAM_VK, VADCOP_VK, 1);
        // Truncated frame (e.g. a minimal-size or cut-off stream).
        assert_eq!(
            ProofFrame::parse(&words[..PROOF_STREAM_WORDS - 1]),
            Err(AggError::WrongLength {
                words: PROOF_STREAM_WORDS - 1
            })
        );
        // Over-long frame (trailing garbage would shift the vadcop VK).
        let mut long = words.clone();
        long.push(0);
        assert_eq!(
            ProofFrame::parse(&long),
            Err(AggError::WrongLength {
                words: PROOF_STREAM_WORDS + 1
            })
        );
        // Degenerate short frames.
        assert_eq!(
            ProofFrame::parse(&[0u64; 2]),
            Err(AggError::WrongLength { words: 2 })
        );
    }

    #[test]
    fn commitment_truncates_words_to_u32() {
        // Publics words are u32 payloads by construction; anything in the
        // high half must be ignored exactly like PublicValues::new_from_u64.
        let mut words = synth_stream(PROGRAM_VK, VADCOP_VK, 0x2222_2222);
        words[HEADER_WORDS + PROGRAM_VK_WORDS] = 0xDEAD_BEEF_2222_2222;
        let frame = ProofFrame::parse(&words).unwrap();
        assert_eq!(frame.commitment(), [0x22u8; 32]);
    }

    #[test]
    fn aggregator_rejects_vk_mismatches() {
        let a = synth_stream(PROGRAM_VK, VADCOP_VK, 1);
        let b = synth_stream([9, 9, 9, 9], VADCOP_VK, 2);
        let c = synth_stream(PROGRAM_VK, [9, 9, 9, 9], 3);

        let mut agg = Aggregator::new();
        agg.ingest(&ProofFrame::parse(&a).unwrap()).unwrap();
        assert_eq!(
            agg.ingest(&ProofFrame::parse(&b).unwrap()),
            Err(AggError::ProgramVkMismatch)
        );
        assert_eq!(
            agg.ingest(&ProofFrame::parse(&c).unwrap()),
            Err(AggError::VadcopVkMismatch)
        );
    }

    #[test]
    fn empty_aggregation_cannot_finalize() {
        assert_eq!(Aggregator::new().finalize(), Err(AggError::NoProofs));
    }

    /// The binding digest recomputed step by step, independent of the
    /// Aggregator internals.
    fn reference_digest(
        program_vk: [u64; 4],
        vadcop_vk: [u64; 4],
        commitments: &[[u8; 32]],
    ) -> [u8; 32] {
        let mut rolling = [0u8; 32];
        for c in commitments {
            let mut preimage = [0u8; 64];
            preimage[..32].copy_from_slice(&rolling);
            preimage[32..].copy_from_slice(c);
            rolling = keccak256(&preimage);
        }
        let mut binding = [0u8; 96];
        for (w, chunk) in program_vk.iter().zip(binding[..32].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        for (w, chunk) in vadcop_vk.iter().zip(binding[32..64].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        binding[64..].copy_from_slice(&rolling);
        keccak256(&binding)
    }

    #[test]
    fn binding_digest_matches_reference() {
        let streams = [
            synth_stream(PROGRAM_VK, VADCOP_VK, 0x1111_1111),
            synth_stream(PROGRAM_VK, VADCOP_VK, 0x2222_2222),
            synth_stream(PROGRAM_VK, VADCOP_VK, 0x3333_3333),
        ];
        let mut agg = Aggregator::new();
        for s in &streams {
            agg.ingest(&ProofFrame::parse(s).unwrap()).unwrap();
        }
        let digest = agg.finalize().unwrap();
        assert_eq!(
            digest,
            reference_digest(
                PROGRAM_VK,
                VADCOP_VK,
                &[[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]]
            )
        );
    }

    /// Shared cross-crate test vector: the server's aggregation submit
    /// validation (`expected_aggregated_commitment` in
    /// zksync-os-server `zisk_aggregation_job_manager.rs`) asserts the
    /// same hex digest for the same inputs. Update both together.
    #[test]
    fn binding_digest_shared_vector() {
        let streams = [
            synth_stream(PROGRAM_VK, VADCOP_VK, 0x1111_1111),
            synth_stream(PROGRAM_VK, VADCOP_VK, 0x2222_2222),
        ];
        let mut agg = Aggregator::new();
        for s in &streams {
            agg.ingest(&ProofFrame::parse(s).unwrap()).unwrap();
        }
        let digest = agg.finalize().unwrap();
        let mut hex = String::new();
        for b in digest {
            hex.push_str(&format!("{b:02x}"));
        }
        assert_eq!(hex, SHARED_VECTOR_DIGEST);
    }

    /// keccak256(le64(1,2,3,4) ‖ le64(5,6,7,8) ‖ keccak(keccak(0^32 ‖ 0x11^32) ‖ 0x22^32)).
    const SHARED_VECTOR_DIGEST: &str =
        "f73b9b6beae4a1c5e9597a42e7c51a8ab67a0e234f0c03e488cc604fd2b711a5";
}
