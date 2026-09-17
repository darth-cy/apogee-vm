//! The shard verifier, from files.
//!
//!     cargo run -p verifier -- <verifying-key> <identity-hex> <public-inputs> <proof>...
//!
//! The key is loaded once, its identity compared with the one given — a verifier
//! takes a program's identity from a channel the prover does not control, never
//! from the key or the proof — and then every proof is verified against the one
//! public-inputs file through `verifier::verify_shard`. `<identity-hex>` is the
//! identity's 32 canonical bytes as 64 lowercase hex digits, little-endian.
//!
//! A statement is proven only when **every one of its shards** is: a shard
//! checks the memory argument's reconciliation over roots the other shards'
//! proofs establish, and says nothing about their circuits. So the proofs
//! given must be exactly the statement's shards, each once, in any order.
//!
//! Exit 0 when they are and every one verifies; 1 naming the first file
//! refused and why, or the shards missing or repeated; 2 on a usage error.

use std::fs;

use verifier::{load_verifying_key, verify_shard, PublicInputs, ShardProof};
use verifier_core::statement_shards;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [key, identity, public, proofs @ ..] = args.as_slice() else {
        usage("expected a key, an identity, the public inputs and at least one proof");
    };
    if proofs.is_empty() {
        usage("expected at least one proof");
    }
    let trusted =
        parse_identity(identity).unwrap_or_else(|| usage("the identity is not 64 hex digits"));
    let vk = load_verifying_key(&read(key)).unwrap_or_else(|e| fail(&format!("{key}: {e}")));
    if vk.identity.to_bytes() != trusted {
        fail(&format!("{key}: the key's identity is not the one given"));
    }
    let public =
        PublicInputs::from_bytes(&read(public)).unwrap_or_else(|e| fail(&format!("{public}: {e}")));
    let mut proven = Vec::with_capacity(proofs.len());
    for path in proofs {
        let proof =
            ShardProof::from_bytes(&read(path)).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
        match verify_shard(&vk, &proof, &public) {
            Ok(()) => println!(
                "{path}: family {} shard {} verifies",
                proof.family, proof.shard_index
            ),
            Err(e) => fail(&format!("{path}: {e}")),
        }
        proven.push((proof.family, proof.shard_index));
    }
    // Every proof passed step 1, so the counts are one per config family, and
    // step 3 bounded their total by the statement's own lists.
    let mut shards = statement_shards(&vk.config, &public.shard_counts);
    shards.sort_unstable();
    proven.sort_unstable();
    if proven != shards {
        fail(&format!(
            "the proofs are not the statement's {} shards, each once",
            shards.len()
        ));
    }
    println!("the statement verifies: {} shards", shards.len());
}

fn parse_identity(hex: &str) -> Option<[u8; 32]> {
    let digits = hex.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, pair) in digits.chunks(2).enumerate() {
        out[i] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(out)
}

fn read(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| fail(&format!("reading {path}: {e}")))
}

fn usage(why: &str) -> ! {
    eprintln!("verifier: {why}");
    eprintln!("usage: verifier <verifying-key> <identity-hex> <public-inputs> <proof>...");
    std::process::exit(2);
}

fn fail(why: &str) -> ! {
    eprintln!("verifier: {why}");
    std::process::exit(1);
}
