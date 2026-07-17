//! End-to-end binding-vector check over the four REAL per-batch
//! `vadcop_final` proofs of the 2026-07-15 aggregation session
//! (ZiSK v0.18.0): loads the proof files, parses them with the guest's
//! own frame parser, runs the full `Aggregator` (the exact code path the
//! guest executes, host keccak backend), and asserts every value pinned
//! in `guest-aggregator/BINDING_VECTOR.md`.
//!
//! The proof files are ~370 KB each and live outside the repo; point
//! `ZISK_AGG_SESSION_DIR` at a directory containing
//! `vadcop-batch-{1..4}.bin` to run this test. Without the variable the
//! test passes vacuously and prints a SKIPPED notice.

use zksync_os_zisk_guest_aggregator as agg;
use zksync_os_zisk_prover_service::aggregator_input::load_proof_stream;

const INNER_PROGRAM_VK: &str = "481748830df5c3b7aa5522333ace2c4b533352637b92fd3c83ecc506c5104ead";
const ROOT_C_VADCOP_FINAL: &str =
    "cf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d";
const COMMITMENTS: [&str; 4] = [
    "95693fd871251f2a04f558f94852d31d4f7b0cd38b0ee2c746bd2851dc701dca",
    "4962160e4e0addc72fe2178dbbf3c5882ca1033790bb968d4fa451485987f99b",
    "e697864dd72ddded6f1818db6618efff8e695714db8492ac50abc9f5d8b6221e",
    "3cbda79d374329af945a0b1d2d73c87b2cd2cadb69ab3d6c03166a690dfff898",
];
const DIGEST: &str = "5f47db9b336cf84b7b7fc49ca77eadb5160e373dc8f12057d719f45d3b2fbd84";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn vk_hex(words: &[u64]) -> String {
    let mut bytes = Vec::with_capacity(words.len() * 8);
    for w in words {
        bytes.extend_from_slice(&w.to_be_bytes());
    }
    hex(&bytes)
}

#[test]
fn real_proofs_reproduce_binding_vector() {
    let Ok(dir) = std::env::var("ZISK_AGG_SESSION_DIR") else {
        eprintln!(
            "SKIPPED: set ZISK_AGG_SESSION_DIR to a directory containing \
             vadcop-batch-{{1..4}}.bin to run real_proofs_reproduce_binding_vector"
        );
        return;
    };
    let dir = std::path::Path::new(&dir);

    let streams: Vec<Vec<u8>> = (1..=4)
        .map(|i| {
            load_proof_stream(&dir.join(format!("vadcop-batch-{i}.bin")))
                .unwrap_or_else(|e| panic!("loading vadcop-batch-{i}.bin: {e:#}"))
        })
        .collect();

    let mut aggregator = agg::Aggregator::new();
    for (i, stream) in streams.iter().enumerate() {
        let words = agg::words_from_bytes(stream).unwrap();
        let frame = agg::ProofFrame::parse(words).unwrap();
        assert_eq!(
            hex(&frame.commitment()),
            COMMITMENTS[i],
            "batch {} commitment",
            i + 1
        );
        if i == 0 {
            assert_eq!(
                vk_hex(frame.program_vk()),
                INNER_PROGRAM_VK,
                "innerProgramVK"
            );
            assert_eq!(
                vk_hex(frame.vadcop_vk()),
                ROOT_C_VADCOP_FINAL,
                "rootCVadcopFinal"
            );
        }
        aggregator.ingest(&frame).unwrap();
    }

    let digest = aggregator.finalize().unwrap();
    assert_eq!(hex(&digest), DIGEST, "binding digest");
}
