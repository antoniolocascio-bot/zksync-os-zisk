//! Inspect a real `cargo-zisk prove --plonk` proof file: parse it with the
//! daemon's mirrored structs and dump the assembled wire sections.
//!
//! Usage: cargo run --example inspect_proof -- <proof.bin>

fn main() {
    let path = std::env::args().nth(1).expect("usage: inspect_proof <proof.bin>");
    let out =
        zksync_os_zisk_prover_service::prover::parse_proof_file(std::path::Path::new(&path))
            .expect("parse proof file");
    println!("proof bytes: {}", out.proof.len());
    println!("public values bytes: {}", out.public_values.len());
    println!("program_vk   = 0x{}", hex(&out.public_values[..32]));
    println!("publics[0..32]  (commitment) = 0x{}", hex(&out.public_values[32..64]));
    let tail = &out.public_values[64..out.public_values.len() - 32];
    println!("publics tail nonzero bytes: {}", tail.iter().filter(|b| **b != 0).count());
    let n = out.public_values.len();
    println!("vadcop_vk    = 0x{}", hex(&out.public_values[n - 32..]));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
