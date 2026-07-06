//! ZiSK guest: proves ZKsync OS block execution using REVM.
//!
//! Every storage read is verified against a merkle proof.
//! The committed output is the BatchPublicInput hash matching the L1 format.
//! There is no unverified path — the guest always runs proven execution.

#![no_main]

use zksync_os_zisk_lib::{crypto::CustomEvmCrypto, executor, types::BatchInput};

ziskos::entrypoint!(main);

fn main() {
    // Install ZiSK-native crypto (keccak, secp256k1, bn254, etc.)
    // before any REVM execution. On the ZiSK target this uses hardware-
    // accelerated circuits; on native it falls back to software.
    revm::install_crypto(CustomEvmCrypto::default());

    // `install_crypto` only covers REVM *precompiles*. Transaction-envelope
    // signature recovery (`TxEnvelope::recover_signer`) dispatches through
    // alloy-consensus's OWN crypto backend, which otherwise falls back to
    // software k256 (the dominant proving cost on tx-heavy batches). Install
    // `CustomEvmCrypto` there too so tx recovery uses the accelerated
    // secp256k1 path (`secp256k1_ecdsa_address_recover_c` below).
    zksync_os_zisk_lib::crypto::install_tx_recovery_provider();

    // `ziskos::io::read()` deserializes with bincode 2.x (`config::standard()`,
    // varint), but `input.bin` was produced with bincode 1.x (fixint) by
    // `export_proven_input_for_emulator`. Read the raw framed slice and
    // deserialize with bincode 1.x to keep `input.bin` byte-for-byte unchanged
    // (sha256 46531ebf…, 4296 B).
    //
    // v0.18.0: the zero-copy reader is `io::read_input_slice()` (returns
    // `&[u8]` on the zkVM target). v1.0.0-alpha had renamed this to
    // `read_slice`; v0.18.0 still uses the original `read_input_slice` name.
    let bytes = ziskos::io::read_input_slice();
    let batch_input: BatchInput =
        bincode::deserialize(bytes).expect("failed to deserialize BatchInput (bincode 1.x)");

    let (_output, commitment) = executor::execute_and_commit(&batch_input);
    let hash_bytes: [u8; 32] = commitment.into();

    // v1.0.0-alpha migration: commit the raw 32-byte keccak output. In v0.16.1
    // `io::commit` wrote bytes as u32 LE chunks, so the guest pre-swapped each
    // 4-byte group. `commit_slice` writes the byte stream directly; verify the
    // public-values byte order against the reference commitment (0x891b61c0…)
    // after emulation and re-introduce a swap here only if it comes out swapped.
    ziskos::io::commit_slice(&hash_bytes);
}

// ---------------------------------------------------------------------------
// Crypto precompile shims (v1.0.0-alpha migration).
//
// `zksync-os-zisk-lib::crypto::CustomEvmCrypto` calls the C-ABI symbols below
// on the ZiSK target. In v0.16.1 these were provided by a patched
// `zksync-os-revm` (an uncommitted `/tmp/zksync-os-revm-patched`); they are not
// present in the v1.0.0-alpha toolchain or any committed crate. v1.0.0-alpha
// exposes equivalent operations as Rust functions under `ziskos::zisklib`.
//
// The synthetic `force_fail` batch performs almost no EVM execution and is not
// expected to invoke any of these precompiles. We provide them as identifying
// panic-stubs so the ELF links; anything the batch actually exercises will
// panic under `ziskemu`, at which point it gets a real `ziskos::zisklib`-backed
// implementation. keccak256 is unaffected (routed via the tiny-keccak patch /
// native-keccak) and is NOT stubbed here.
// ---------------------------------------------------------------------------
macro_rules! precompile_stub {
    ($name:ident ( $($arg:ident : $ty:ty),* ) $(-> $ret:ty)?) => {
        #[no_mangle]
        pub extern "C" fn $name( $($arg : $ty),* ) $(-> $ret)? {
            $( let _ = $arg; )*
            panic!(concat!(
                "ZiSK crypto precompile `", stringify!($name),
                "` is not implemented for v1.0.0-alpha (batch was not expected to \
                 invoke it); wire it to ziskos::zisklib to support batches that do."
            ));
        }
    };
}

precompile_stub!(sha256_c(input: *const u8, input_len: usize, output: *mut u8));
precompile_stub!(bn254_g1_add_c(p1: *const u8, p2: *const u8, ret: *mut u8) -> u8);
precompile_stub!(bn254_g1_mul_c(point: *const u8, scalar: *const u8, ret: *mut u8) -> u8);
precompile_stub!(bn254_pairing_check_c(pairs: *const u8, num_pairs: usize) -> u8);
precompile_stub!(secp256k1_ecdsa_verify_and_address_recover_c(sig: *const u8, msg: *const u8, pk: *const u8, output: *mut u8) -> u8);
precompile_stub!(modexp_bytes_c(base_ptr: *const u8, base_len: usize, exp_ptr: *const u8, exp_len: usize, modulus_ptr: *const u8, modulus_len: usize, ret_ptr: *mut u8) -> usize);
precompile_stub!(blake2b_compress_c(rounds: u32, h: *mut u64, m: *const u64, t: *const u64, f: u8));
precompile_stub!(secp256r1_ecdsa_verify_c(msg: *const u8, sig: *const u8, pk: *const u8) -> bool);
precompile_stub!(verify_kzg_proof_c(z: *const u8, y: *const u8, commitment: *const u8, proof: *const u8) -> bool);
precompile_stub!(bls12_381_g1_add_c(ret: *mut u8, a: *const u8, b: *const u8) -> u8);
precompile_stub!(bls12_381_g1_msm_c(ret: *mut u8, pairs: *const u8, num_pairs: usize) -> u8);
precompile_stub!(bls12_381_g2_add_c(ret: *mut u8, a: *const u8, b: *const u8) -> u8);
precompile_stub!(bls12_381_g2_msm_c(ret: *mut u8, pairs: *const u8, num_pairs: usize) -> u8);
precompile_stub!(bls12_381_pairing_check_c(pairs: *const u8, num_pairs: usize) -> u8);
precompile_stub!(bls12_381_fp_to_g1_c(ret: *mut u8, fp: *const u8) -> u8);
precompile_stub!(bls12_381_fp2_to_g2_c(ret: *mut u8, fp2: *const u8) -> u8);

// ---------------------------------------------------------------------------
// Accelerated secp256k1 ECDSA public-key/address recovery.
//
// `zksync-os-zisk-lib::crypto::impls` calls this C-ABI symbol on the ZiSK
// target from BOTH the REVM `Crypto::secp256k1_ecrecover` precompile and
// alloy-consensus's `CryptoProvider::recover_signer_unchecked` (transaction
// recovery). Unlike the panic-stubs above, this one is exercised by real
// batches (every L2 tx signature), so it is a genuine implementation backed
// by ziskos's accelerated secp256k1 circuits.
// ---------------------------------------------------------------------------

/// Recover the signer's Ethereum-address hash from an ECDSA signature.
///
/// `sig` points to 64 bytes (r ‖ s, big-endian), `recid` is the y-parity
/// (0 or 1), `msg` points to the 32-byte prehash. On success `output[0..32]`
/// receives `keccak256(pubkey_x ‖ pubkey_y)` with the top 12 bytes zeroed, so
/// `output[12..32]` is the 20-byte address — matching REVM's k256 reference
/// (`hash[..12].fill(0)`) and impls.rs's `Address::from_slice(&output[12..])`.
/// Returns 0 on success, 1 on failure.
///
/// The public key is recovered via ziskos v0.18.0's `zkvm_secp256k1_ecrecover`
/// (a `#[no_mangle]` C symbol from `ziskos::zisklib::zkvm_accelerators` on the
/// zisk target). On-target it uses the accelerated secp256k1 add/dbl ops
/// (0xf4/0xf5) + arith_eq circuits — NOT software k256. The signature `s` is
/// not normalized here: alloy's `recover_signer` enforces EIP-2 low-`s` before
/// dispatching, and negating `s` while flipping `recid` yields the same point,
/// so the recovered key (and thus the address) is identical to the k256 path.
#[no_mangle]
pub extern "C" fn secp256k1_ecdsa_address_recover_c(
    sig: *const u8,
    recid: u8,
    msg: *const u8,
    output: *mut u8,
) -> u8 {
    // ziskos accelerated ecrecover. C ABI (zkvm_accelerators.h):
    //   zkvm_status zkvm_secp256k1_ecrecover(const zkvm_secp256k1_hash* msg,
    //       const zkvm_secp256k1_signature* sig, uint8_t recid,
    //       zkvm_secp256k1_pubkey* output);
    // hash = bytes32, signature = pubkey = bytes64 (all thin ptrs);
    // zkvm_status is a C enum { ZKVM_EOK = 0, ZKVM_EFAIL = -1 } => c_int/i32.
    extern "C" {
        fn zkvm_secp256k1_ecrecover(
            msg: *const u8,
            sig: *const u8,
            recid: u8,
            output: *mut u8,
        ) -> i32;
    }

    // Recover the 64-byte uncompressed public key (x ‖ y, big-endian).
    let mut pubkey = [0u8; 64];
    let status = unsafe { zkvm_secp256k1_ecrecover(msg, sig, recid, pubkey.as_mut_ptr()) };
    if status != 0 {
        return 1;
    }

    // address = keccak256(pubkey)[12..]; zero the top 12 bytes to match the
    // reference precompile output. Uses the ZiSK-accelerated keccak.
    let hash = zksync_os_zisk_lib::hash::keccak256(&pubkey);
    let out = unsafe { core::slice::from_raw_parts_mut(output, 32) };
    out[..12].fill(0);
    out[12..].copy_from_slice(&hash.as_slice()[12..]);
    0
}
