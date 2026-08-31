//! Witness-soundness testing: does the guest VERIFY its witness?
//!
//! The native cross-check answers whether the guest executes an honest witness
//! the way native ZKsync OS does. This answers the other question: for a
//! mutated witness of the SAME statement, does the guest either reject it, or
//! commit the honest value? A mutation the guest accepts and commits
//! differently is two witnesses for one statement, which is a soundness
//! defect. See `docs/witness-soundness-testing.md`.

use revm::primitives::{Address, B256};
use serde::Serialize;
use zksync_os_zisk_lib::executor;
use zksync_os_zisk_lib::hash::keccak256;
use zksync_os_zisk_lib::types::{BatchInput, L2ToL1LogEntry, TxAuth};

/// A supplier of the witness it wants the guest to accept.
///
/// The oracle builds a whole `BatchInput` rather than patching bytes, so it can
/// tell a well-formed lie: a forged value with the sibling path recomputed to
/// match it. Garbage bytes only prove that some check exists, not that it binds
/// what it must bind.
pub trait WitnessOracle {
    /// Stable identifier. A finding reproduces from the case and this name.
    fn name(&self) -> &str;
    /// The witness this oracle wants the guest to accept. `None` when the case
    /// offers no site for it.
    fn witness(&self, honest: &BatchInput) -> Option<BatchInput>;
}

/// Hash of every field the commitment is a statement about. An oracle that
/// changes this asks for a proof of something else, so the harness fails the
/// run instead of judging the guest.
///
/// A field is statement when the guest is not its verifier: it either names the
/// transition (the chain, the tier, the pre-state, the blocks and their
/// transactions), or L1 pins it outside the guest (the chain configuration and
/// the data-availability declaration). Every other field is witness — data the
/// guest must check against the statement, and therefore data an oracle may lie
/// about.
pub fn statement_digest(input: &BatchInput) -> B256 {
    let mut buf = Vec::new();

    // The schema the rest of the input is read under. Two wire versions are two
    // different requests, not one request and a lie about it.
    push_u64(&mut buf, u64::from(input.version));
    // The chain and the state transition function tier. Each selects formulas
    // the commitment is computed with, and L1 pins both.
    push_u64(&mut buf, input.chain_id);
    push_u64(&mut buf, u64::from(input.spec_id));
    push_u64(&mut buf, u64::from(input.protocol_version_minor));

    let meta = &input.batch_meta;
    // The pre-state the transition starts from. `state_before` commits every
    // word here verbatim, so a change asks about a different chain state. The
    // witness that must reproduce them — `previous_block_hashes`, the storage
    // proofs, the tree update — stays mutable.
    push_b256(&mut buf, &meta.tree_root_before);
    push_u64(&mut buf, meta.leaf_count_before);
    push_u64(&mut buf, meta.block_number_before);
    push_u64(&mut buf, meta.last_block_timestamp_before);
    push_b256(&mut buf, &meta.block_hashes_blake_before);
    // The chain configuration, which L1 pins through `chain_config_hash`.
    push_u64(&mut buf, u64::from(meta.fri_proof_verification_enabled));
    push_u64(&mut buf, meta.max_tx_gas_limit);
    push_u64(&mut buf, u64::from(meta.pubdata_content));
    // The data-availability declaration. L1 compares the published payload
    // against the commitment the guest derives from these three, so the guest
    // is not their verifier and this harness cannot judge a change to them.
    push_u64(&mut buf, u64::from(meta.da_commitment_scheme));
    push_bytes(&mut buf, &meta.pubdata);
    push_u64(&mut buf, meta.blob_versioned_hashes.len() as u64);
    for versioned_hash in &meta.blob_versioned_hashes {
        push_b256(&mut buf, versioned_hash);
    }

    push_u64(&mut buf, input.blocks.len() as u64);
    for block in &input.blocks {
        // Which block this is, and the context the header commits and the EVM
        // observes. A change to any of them is a different block.
        push_u64(&mut buf, block.number);
        push_u64(&mut buf, block.timestamp);
        push_u64(&mut buf, block.base_fee);
        push_u64(&mut buf, block.gas_limit);
        push_bytes(&mut buf, block.coinbase.as_slice());
        push_b256(&mut buf, &block.prev_randao);
        // The transactions as the chain accepted them. `TxInput` also carries
        // the server's execution hints (`gas_used_override`, `force_fail`),
        // which no user submits and which the guest is meant to check, so those
        // two stay on the witness side.
        push_u64(&mut buf, block.transactions.len() as u64);
        for tx in &block.transactions {
            match tx.chain_id {
                Some(chain_id) => {
                    push_u64(&mut buf, 1);
                    push_u64(&mut buf, chain_id);
                }
                None => push_u64(&mut buf, 0),
            }
            push_auth(&mut buf, &tx.auth);
        }
    }

    // Deliberately absent, because the guest authenticates each of them against
    // the statement above: `bytecodes`, `previous_block_hashes`,
    // `upgrade_tx_hash`, `multichain_root`, `sl_chain_id`, `tree_update`,
    // `account_preimages_after`, `interop_proofs`, and, per block,
    // `account_preimages`, `block_hashes`, `storage_proofs`,
    // `block_header_hash`, `expected_tree_root`, `l2_to_l1_logs`.
    keccak256(&buf)
}

/// The transaction's identity: which authentication variant it uses, and the
/// bytes every execution field is derived from.
fn push_auth(buf: &mut Vec<u8>, auth: &TxAuth) {
    match auth {
        TxAuth::L1 {
            tx_hash,
            abi_encoded,
        } => {
            push_u64(buf, 0);
            push_b256(buf, tx_hash);
            push_bytes(buf, abi_encoded);
        }
        TxAuth::Upgrade {
            tx_hash,
            abi_encoded,
        } => {
            push_u64(buf, 1);
            push_b256(buf, tx_hash);
            push_bytes(buf, abi_encoded);
        }
        TxAuth::L2 { signed_bytes } => {
            push_u64(buf, 2);
            push_bytes(buf, signed_bytes);
        }
        TxAuth::System {
            tx_hash,
            encoded_2718,
        } => {
            push_u64(buf, 3);
            push_b256(buf, tx_hash);
            push_bytes(buf, encoded_2718);
        }
    }
}

fn push_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn push_b256(buf: &mut Vec<u8>, value: &B256) {
    buf.extend_from_slice(value.as_slice());
}

/// Length-prefixed, so no two field sequences share an encoding.
fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    push_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

/// What the guest did with an oracle's witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// The guest refused the witness. `assert` records which check fired.
    Rejected { assert: String },
    /// The guest accepted and committed the honest value: the mutated bytes
    /// bind nothing.
    AcceptedIdentical,
    /// The guest accepted and committed a different transition. A finding.
    AcceptedDifferent { honest: B256, mutated: B256 },
}

/// The verdict for a witness the guest accepted.
pub fn classify(honest: B256, mutated: B256) -> Outcome {
    if honest == mutated {
        Outcome::AcceptedIdentical
    } else {
        Outcome::AcceptedDifferent { honest, mutated }
    }
}

/// What one oracle produced on one case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OracleVerdict {
    /// The case offers this oracle no site to act on.
    NoSite,
    /// The oracle moved the statement, so the guest never ran. The harness is
    /// at fault here, not the guest.
    StatementMoved { produced: B256 },
    /// The guest ran on the oracle's witness.
    Judged(Outcome),
}

impl core::fmt::Display for OracleVerdict {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OracleVerdict::NoSite => write!(f, "no site in this case"),
            OracleVerdict::StatementMoved { produced } => write!(
                f,
                "HARNESS ERROR: the oracle moved the statement digest to {produced}"
            ),
            OracleVerdict::Judged(Outcome::Rejected { assert }) => {
                write!(f, "rejected: {assert}")
            }
            OracleVerdict::Judged(Outcome::AcceptedIdentical) => {
                write!(f, "accepted, identical commitment")
            }
            OracleVerdict::Judged(Outcome::AcceptedDifferent { honest, mutated }) => write!(
                f,
                "FINDING: accepted, committed {mutated} where the honest witness committed {honest}"
            ),
        }
    }
}

/// One oracle's verdict on one case.
#[derive(Clone, Debug, Serialize)]
pub struct OracleReport {
    pub oracle: String,
    #[serde(flatten)]
    pub verdict: OracleVerdict,
}

/// The honest run every oracle of a case is judged against.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct HonestRun {
    /// The digest every oracle must preserve.
    pub statement: B256,
    /// The commitment the honest witness produces.
    pub commitment: B256,
}

/// One case swept with a set of oracles.
#[derive(Clone, Debug, Serialize)]
pub struct WitnessSoundness {
    #[serde(flatten)]
    pub honest: HonestRun,
    pub oracles: Vec<OracleReport>,
}

impl WitnessSoundness {
    /// The first oracle the guest accepted with a different commitment. A
    /// soundness defect.
    pub fn finding(&self) -> Option<&OracleReport> {
        self.oracles.iter().find(|report| {
            matches!(
                report.verdict,
                OracleVerdict::Judged(Outcome::AcceptedDifferent { .. })
            )
        })
    }

    /// The first oracle that moved the statement. The harness is at fault.
    pub fn harness_error(&self) -> Option<&OracleReport> {
        self.oracles
            .iter()
            .find(|report| matches!(report.verdict, OracleVerdict::StatementMoved { .. }))
    }
}

/// Judge one oracle against the honest run of the same case.
pub fn evaluate(honest: &BatchInput, run: &HonestRun, oracle: &dyn WitnessOracle) -> OracleVerdict {
    let Some(mutated) = oracle.witness(honest) else {
        return OracleVerdict::NoSite;
    };
    let produced = statement_digest(&mutated);
    if produced != run.statement {
        return OracleVerdict::StatementMoved { produced };
    }
    match commit(&mutated) {
        Err(assert) => OracleVerdict::Judged(Outcome::Rejected { assert }),
        Ok(commitment) => OracleVerdict::Judged(classify(run.commitment, commitment)),
    }
}

/// Sweep one honest batch with every oracle, computing the honest commitment
/// once. An honest witness the guest refuses is a harness error: the case gives
/// nothing to compare against.
pub fn evaluate_all(
    honest: &BatchInput,
    oracles: &[Box<dyn WitnessOracle>],
) -> anyhow::Result<WitnessSoundness> {
    let commitment = commit(honest).map_err(|assert| {
        anyhow::anyhow!("the guest rejected the honest witness of this case: {assert}")
    })?;
    let run = HonestRun {
        statement: statement_digest(honest),
        commitment,
    };
    let oracles = oracles
        .iter()
        .map(|oracle| OracleReport {
            oracle: oracle.name().to_string(),
            verdict: evaluate(honest, &run, oracle.as_ref()),
        })
        .collect();
    Ok(WitnessSoundness {
        honest: run,
        oracles,
    })
}

/// The guest's commitment for one witness, or the assert that rejected it.
/// In-guest asserts are the rejection mechanism, so a panic is a verdict.
fn commit(input: &BatchInput) -> Result<B256, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor::execute_and_commit(input).1
    }))
    .map_err(|payload| crate::panic_message(payload.as_ref()))
}

/// The oracles a sweep runs. A new case is one implementation of
/// [`WitnessOracle`] and one line here.
pub fn oracles() -> Vec<Box<dyn WitnessOracle>> {
    let mut all: Vec<Box<dyn WitnessOracle>> = vec![Box::new(Honest), Box::new(UnboundL2ToL1Logs)];
    all.extend(metadata::oracles());
    all.extend(preimages::oracles());
    all.extend(proofs::oracles());
    all
}

/// Campaign oracle axes. Each module is owned by one campaign agent, so
/// parallel agents never edit the same file.
pub mod metadata;
pub mod preimages;
pub mod proofs;

/// The identity.
///
/// Its verdict is `AcceptedIdentical` on every case, which pins the harness
/// itself: a harness that reports anything else here compares two runs that
/// were never comparable.
pub struct Honest;

impl WitnessOracle for Honest {
    fn name(&self) -> &str {
        "honest"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        Some(honest.clone())
    }
}

/// A fabricated L2→L1 log record, appended to the first block's witness list.
///
/// The negative control. `BlockInput::l2_to_l1_logs` authenticates nothing: the
/// guest folds its own journal-derived log set into the commitment and never
/// reads this field. A correct guest therefore accepts this witness and commits
/// the honest value, which is what tells a reader that the harness distinguishes
/// unbound data from bound data. The record is appended rather than edited
/// because the honest list is often empty, and an oracle with no site
/// demonstrates nothing.
pub struct UnboundL2ToL1Logs;

/// Recognizable in a report, and distinct from any record a block produces.
const FABRICATED_LOG: L2ToL1LogEntry = L2ToL1LogEntry {
    l2_shard_id: 0,
    is_service: true,
    tx_number_in_block: 0,
    sender: Address::ZERO,
    key: B256::repeat_byte(0xa1),
    value: B256::repeat_byte(0xa2),
};

impl WitnessOracle for UnboundL2ToL1Logs {
    fn name(&self) -> &str {
        "unbound_l2_to_l1_logs"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        mutated
            .blocks
            .first_mut()?
            .l2_to_l1_logs
            .push(FABRICATED_LOG);
        Some(mutated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dump::tests::empty_block_bundle;
    use crate::dump::{build_batch_input, HeaderHashCheck};

    /// The honest witness of a self-consistent empty AtlasV3 block. The guest
    /// runs it end to end, so every verdict below is a real guest verdict.
    fn honest_batch() -> BatchInput {
        build_batch_input(&empty_block_bundle(), HeaderHashCheck::Armed).batch_input
    }

    fn sweep(oracle: Box<dyn WitnessOracle>) -> OracleVerdict {
        let honest = honest_batch();
        let sweep = evaluate_all(&honest, &[oracle]).expect("the guest accepts the honest witness");
        sweep.oracles[0].verdict.clone()
    }

    /// The harness's own floor: the identity oracle reproduces the honest
    /// commitment.
    #[test]
    fn the_identity_oracle_commits_the_honest_value() {
        assert_eq!(
            sweep(Box::new(Honest)),
            OracleVerdict::Judged(Outcome::AcceptedIdentical)
        );
    }

    /// The negative control: unbound witness data moves no commitment, so the
    /// harness reports no finding for it.
    #[test]
    fn a_fabricated_l2_to_l1_log_is_accepted_unchanged() {
        assert_eq!(
            sweep(Box::new(UnboundL2ToL1Logs)),
            OracleVerdict::Judged(Outcome::AcceptedIdentical)
        );
    }

    /// Moves a statement field. It exists to fire the gate, never to judge the
    /// guest, so it stays out of the shipped catalogue.
    struct MovesTheBlockTimestamp;

    impl WitnessOracle for MovesTheBlockTimestamp {
        fn name(&self) -> &str {
            "moves_the_block_timestamp"
        }

        fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
            let mut mutated = honest.clone();
            mutated.blocks.first_mut()?.timestamp += 1;
            Some(mutated)
        }
    }

    /// The gate stops an oracle that asks for a proof of something else before
    /// the guest runs, and it names the oracle that did it.
    #[test]
    fn the_gate_stops_an_oracle_that_moves_the_statement() {
        let honest = honest_batch();
        let sweep = evaluate_all(&honest, &[Box::new(MovesTheBlockTimestamp)]).expect("honest run");
        let moved = sweep.harness_error().expect("the gate must fire");
        assert_eq!(moved.oracle, "moves_the_block_timestamp");
        let OracleVerdict::StatementMoved { produced } = moved.verdict else {
            panic!("expected a moved statement, got {}", moved.verdict);
        };
        assert_ne!(produced, sweep.honest.statement);
        assert!(sweep.finding().is_none(), "a moved statement is no finding");
    }

    /// Claims an upgrade transaction the batch does not carry.
    ///
    /// `upgrade_tx_hash` is witness: the guest authenticates it against the
    /// batch's own transactions, in both directions. The oracle exists to prove
    /// that the harness records a rejection with the assert that fired, so it
    /// stays out of the shipped catalogue.
    struct ForgedUpgradeTxHash;

    impl WitnessOracle for ForgedUpgradeTxHash {
        fn name(&self) -> &str {
            "forged_upgrade_tx_hash"
        }

        fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
            let mut mutated = honest.clone();
            mutated.batch_meta.upgrade_tx_hash = B256::repeat_byte(0xee);
            Some(mutated)
        }
    }

    /// A rejection carries the check that fired, so a reader can tell a
    /// mutation that reached the check under test from one that tripped an
    /// unrelated assert first.
    #[test]
    fn a_rejected_witness_records_the_assert_that_fired() {
        let OracleVerdict::Judged(Outcome::Rejected { assert }) =
            sweep(Box::new(ForgedUpgradeTxHash))
        else {
            panic!("the guest must reject a forged upgrade_tx_hash");
        };
        assert!(
            assert.contains("upgrade_tx_hash must be nonzero"),
            "unexpected assert: {assert}"
        );
    }

    /// A correct guest produces no `AcceptedDifferent`, so the finding branch is
    /// pinned on the classifier itself.
    #[test]
    fn a_different_commitment_from_an_accepted_witness_is_a_finding() {
        let honest = B256::repeat_byte(0x01);
        let mutated = B256::repeat_byte(0x02);
        assert_eq!(
            classify(honest, mutated),
            Outcome::AcceptedDifferent { honest, mutated }
        );
        let report = OracleReport {
            oracle: "synthetic".to_string(),
            verdict: OracleVerdict::Judged(classify(honest, mutated)),
        };
        let sweep = WitnessSoundness {
            honest: HonestRun {
                statement: B256::ZERO,
                commitment: honest,
            },
            oracles: vec![report],
        };
        assert_eq!(sweep.finding().expect("a finding").oracle, "synthetic");
        assert!(sweep.harness_error().is_none());
    }
}
