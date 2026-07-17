//! Dump a cargo-zisk --plonk proof file in the server wire format (hex).
fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .expect("usage: dump_wire <proof.bin>");
    let out = zksync_os_zisk_prover_service::prover::parse_proof_file(std::path::Path::new(&path))?;
    println!(
        "PROOF({}): {}",
        out.proof.len(),
        out.proof
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!(
        "PUBLIC_VALUES({}): {}",
        out.public_values.len(),
        out.public_values
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    Ok(())
}
