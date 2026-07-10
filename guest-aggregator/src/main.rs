//! ZiSK aggregator guest: verifies N `vadcop_final` proofs of the STF guest
//! and commits to their chained batch commitments (plan task 2.7).
//!
//! Verification runs pil2-proofman's `proofman-verifier` via ZiSK's own
//! `ziskos::zisklib::verify_zisk_proof` (no_std, Poseidon2-16 transcript and
//! Merkle hashing through the ZiSK poseidon2 precompile). Only non-minimal
//! proofs are accepted: the minimal/compressed variant hashes with
//! Poseidon2-8, which has no precompile and would run the permutation in
//! software.
//!
//! Input framing (host writes consecutive `write_input_slice` frames):
//!   slice 0: u64 LE — the number of proofs N (N >= 1)
//!   slice 1..=N: one serialized proof each, exactly the byte stream
//!     `cargo-zisk` clients obtain from `get_proof_bytes()`:
//!       [minimal(1 word)][n_publics=68][program_vk(4)][publics(64)]
//!       [proof body][vadcop_vk(4)]
//!     (u64 little-endian words; `publics[0..8]` carry the STF guest's
//!     batch-commitment u32 words.)
//!
//! Committed output (PROVISIONAL layout — the L1 binding scheme is decided
//! with tasks 7.x/8; both inner VKs are prover-supplied input here, so they
//! MUST be part of the committed output for the proof to bind them):
//!   keccak256(
//!       program_vk words as 8-byte LE each (32 bytes)
//!    ‖  vadcop_vk  words as 8-byte LE each (32 bytes)
//!    ‖  rolling
//!   )
//!   where rolling = fold(keccak256, [0u8; 32], commitment_1 .. commitment_N)
//!   and commitment_i = publics[0..8] of proof i as u32-LE bytes (32 bytes),
//!   matching the STF guest's `commit_slice` packing.

#![no_main]

use alloy_primitives::keccak256;

ziskos::entrypoint!(main);

/// Words preceding the publics in a serialized proof: [minimal][n_publics].
const HEADER_WORDS: usize = 2;
const PROGRAM_VK_WORDS: usize = 4;
const PUBLICS_WORDS: usize = 64;
const VADCOP_VK_WORDS: usize = 4;
const COMMITMENT_WORDS: usize = 8;

fn main() {
    let count_bytes = ziskos::io::read_input_slice();
    assert_eq!(count_bytes.len(), 8, "count frame must be 8 bytes");
    let n = u64::from_le_bytes(count_bytes.try_into().unwrap()) as usize;
    assert!(n >= 1, "at least one proof required");

    let mut program_vk = [0u64; PROGRAM_VK_WORDS];
    let mut vadcop_vk = [0u64; VADCOP_VK_WORDS];
    let mut rolling = [0u8; 32];

    for i in 0..n {
        let proof_bytes = ziskos::io::read_input_slice();
        let (prefix, words, suffix) = unsafe { proof_bytes.align_to::<u64>() };
        assert!(
            prefix.is_empty() && suffix.is_empty(),
            "proof {i}: input frame not u64-aligned"
        );
        assert!(
            words.len() > HEADER_WORDS + PROGRAM_VK_WORDS + PUBLICS_WORDS + VADCOP_VK_WORDS,
            "proof {i}: too short"
        );
        assert_eq!(words[0], 0, "proof {i}: minimal proofs are not accepted");

        // All aggregated proofs must come from one guest and one recursive
        // setup; the shared values are bound into the committed output.
        let pvk = &words[HEADER_WORDS..HEADER_WORDS + PROGRAM_VK_WORDS];
        let vvk = &words[words.len() - VADCOP_VK_WORDS..];
        if i == 0 {
            program_vk.copy_from_slice(pvk);
            vadcop_vk.copy_from_slice(vvk);
        } else {
            assert_eq!(pvk, program_vk, "proof {i}: program VK mismatch");
            assert_eq!(vvk, vadcop_vk, "proof {i}: vadcop VK mismatch");
        }

        assert!(
            ziskos::zisklib::verify_zisk_proof(words),
            "proof {i}: verification failed"
        );

        // Chain the batch commitment (STF guest publics words 0..8, one u32
        // per word, packed LE exactly as the STF guest committed them).
        let publics = &words[HEADER_WORDS + PROGRAM_VK_WORDS..];
        let mut commitment = [0u8; COMMITMENT_WORDS * 4];
        for (w, chunk) in publics[..COMMITMENT_WORDS]
            .iter()
            .zip(commitment.chunks_exact_mut(4))
        {
            chunk.copy_from_slice(&(*w as u32).to_le_bytes());
        }
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&rolling);
        preimage[32..].copy_from_slice(&commitment);
        rolling = keccak256(preimage).0;
    }

    let mut binding = [0u8; 96];
    for (w, chunk) in program_vk.iter().zip(binding[..32].chunks_exact_mut(8)) {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    for (w, chunk) in vadcop_vk.iter().zip(binding[32..64].chunks_exact_mut(8)) {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    binding[64..].copy_from_slice(&rolling);
    ziskos::io::commit_slice(keccak256(binding).as_slice());
}
