//! **The one thing a proving run archives: the proof.**
//!
//! Since S-STREAM the prover streams, and streaming has no `TraceArchive` —
//! the whole point is that no shard's columns outlive the batch that proves
//! them (`docs/spec/streaming.md`). What a run still has to leave behind is the
//! *proof*, because recursion development reads it back: a recursion guest's
//! input is a base proof, and producing one is a quarter of an hour that
//! nobody should pay twice.
//!
//! # Three of the four are the `verifier` CLI's files
//!
//! Four files under one directory, each the bare `to_bytes()` payload with no
//! header and no framing of this module's own:
//!
//! ```text
//!   <stem>.vk         VerifyingKey::to_bytes
//!   <stem>.identity   the identity this run claims, 64 lowercase hex digits + newline
//!   <stem>.public     PublicInputs::to_bytes   (the block's own statement)
//!   <stem>.block      BlockProof::to_bytes
//! ```
//!
//! `verifier block <vk> <identity-hex> <public> <block>` reads `.vk`, `.public`
//! and `.block` as they are, and `crates/verifier/tests/cli.rs` writes them
//! through this module rather than through a local closure, which is what keeps
//! the two from drifting. **Its identity is not `.identity`.** The CLI takes
//! the 64 hex digits themselves, and a verifier supplies its own:
//!
//! ```text
//!   verifier block <stem>.vk <identity from your own channel> <stem>.public <stem>.block
//! ```
//!
//! **`.identity` is the prover's claim, and nothing reads it as more.** A key
//! recomputes its own identity when it loads, so the key is not its own
//! authority for it: what makes a proof a proof *of a particular program* is a
//! comparison against a value from a channel the prover does not control
//! (`host::verify`'s doc comment). Writing it beside the proof records what
//! this run claimed; it does not make the claim trustworthy, and [`read_proof`]
//! hands the bytes back without checking them against anything. So
//! `"$(cat <stem>.identity)"` in the CLI's identity slot checks a proof against
//! its prover's own claim — fine for re-reading a proof you produced, and
//! evidence of nothing to anyone else.
//!
//! **`<stem>.public` is redundant and is written anyway.** `BlockProof::
//! to_bytes` already carries the statement (`crates/verifier-core/src/
//! block.rs`), so [`read_proof`] could reconstruct it — but the CLI takes it as
//! a file of its own, and a reader should not have to write a script to
//! produce one.
//!
//! The `.vk` is the large file: it carries every registered family's
//! `CircuitArtifact`, and the delegation artifacts are megabytes. It is written
//! unconditionally. A key cache nobody validates is worse than tens of MB,
//! and a proof whose key is missing is not a proof anyone can check.

use std::fs;
use std::path::{Path, PathBuf};

use verifier_core::{BlockProof, PublicInputs, VerifyingKey};

/// Where a proved block's four files landed.
///
/// Returned so that a caller can report the paths without rebuilding them from
/// the stem, and so that a test can assert on them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofPaths {
    pub vk: PathBuf,
    pub identity: PathBuf,
    pub public: PathBuf,
    pub block: PathBuf,
}

impl ProofPaths {
    /// The four paths `write_proof` would use, without writing anything.
    pub fn new(dir: &Path, stem: &str) -> ProofPaths {
        ProofPaths {
            vk: dir.join(format!("{stem}.vk")),
            identity: dir.join(format!("{stem}.identity")),
            public: dir.join(format!("{stem}.public")),
            block: dir.join(format!("{stem}.block")),
        }
    }
}

/// The 64 lowercase hex digits of a program identity, as the CLI takes them.
///
/// Byte order is exactly `to_bytes()`'s, which is what
/// `crates/verifier/src/main.rs` parses back — there is no second convention.
pub fn identity_hex(vk: &VerifyingKey) -> String {
    vk.identity
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Write the four files under `dir`, creating it if it is not there.
///
/// The statement written is the block's own (`block.statement()`), never a
/// second copy a caller supplies: two statements that could disagree is the
/// mistake `host::verify` exists to make unmakeable, and this function makes
/// it the same way.
pub fn write_proof(
    dir: &Path,
    stem: &str,
    vk: &VerifyingKey,
    block: &BlockProof,
) -> Result<ProofPaths, String> {
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let paths = ProofPaths::new(dir, stem);
    let write = |path: &Path, bytes: &[u8]| -> Result<(), String> {
        fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
    };
    write(&paths.vk, &vk.to_bytes())?;
    write(
        &paths.identity,
        format!("{}\n", identity_hex(vk)).as_bytes(),
    )?;
    write(&paths.public, &block.statement().to_bytes())?;
    write(&paths.block, &block.to_bytes())?;
    Ok(paths)
}

/// Read the four files back: the inverse of [`write_proof`].
///
/// Each file goes through its own type's decoder, so a truncated or corrupted
/// file is named rather than producing a half-decoded value. The key goes
/// through `load_verifying_key`, which is the loader with the load rules —
/// it recomputes the SRS digest from the key's own points and revalidates every
/// circuit against the registry (`docs/spec/shard-proof.md` §7) — and not
/// through `VerifyingKey::from_bytes`, which checks encoding only.
///
/// The identity comes back as the 32 bytes, parsed from the file's hex. It is
/// **not** compared against the key's: a reader that wants that comparison
/// writes it, against a value from a channel the prover does not control.
pub fn read_proof(
    dir: &Path,
    stem: &str,
) -> Result<(VerifyingKey, [u8; 32], PublicInputs, BlockProof), String> {
    let paths = ProofPaths::new(dir, stem);
    let read = |path: &Path| -> Result<Vec<u8>, String> {
        fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
    };
    let vk = crate::load_verifying_key(&read(&paths.vk)?)
        .map_err(|e| format!("{}: {e}", paths.vk.display()))?;
    let identity = parse_identity(&read(&paths.identity)?)
        .map_err(|e| format!("{}: {e}", paths.identity.display()))?;
    let public = PublicInputs::from_bytes(&read(&paths.public)?)
        .map_err(|e| format!("{}: {e}", paths.public.display()))?;
    let block = BlockProof::from_bytes(&read(&paths.block)?)
        .map_err(|e| format!("{}: {e}", paths.block.display()))?;
    Ok((vk, identity, public, block))
}

/// 64 hex digits, with whatever whitespace an editor left around them.
fn parse_identity(bytes: &[u8]) -> Result<[u8; 32], String> {
    let text = core::str::from_utf8(bytes).map_err(|_| "not UTF-8".to_string())?;
    let text = text.trim();
    if text.len() != 64 {
        return Err(format!("{} hex digits, not 64", text.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)
            .map_err(|_| format!("byte {i} is not hex"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use verifier_core::{BoundaryFinals, GkrProof, ShardProof};

    /// The four names: the stem, and one extension each.
    #[test]
    fn the_four_paths_are_the_stem_and_its_four_extensions() {
        let p = ProofPaths::new(Path::new("/tmp/out"), "mini-block");
        assert_eq!(p.vk, Path::new("/tmp/out/mini-block.vk"));
        assert_eq!(p.identity, Path::new("/tmp/out/mini-block.identity"));
        assert_eq!(p.public, Path::new("/tmp/out/mini-block.public"));
        assert_eq!(p.block, Path::new("/tmp/out/mini-block.block"));
    }

    /// The hex the CLI parses back, and nothing else.
    ///
    /// `crates/verifier/src/main.rs` takes identity as 64 lowercase hex digits
    /// in `to_bytes()` order, and the file spells the run's claim the same way,
    /// so a reader compares it with its own trusted value as one string.
    #[test]
    fn the_identity_file_round_trips_through_the_cli_s_own_spelling() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(3);
        }
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex.len(), 64);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()));
        assert_eq!(parse_identity(hex.as_bytes()), Ok(bytes));
        // The trailing newline `write_proof` adds, and an editor's whitespace.
        assert_eq!(parse_identity(format!("{hex}\n").as_bytes()), Ok(bytes));
        assert_eq!(parse_identity(format!("  {hex} \n").as_bytes()), Ok(bytes));
        // And what is refused, by name rather than by a half-decoded value.
        assert!(parse_identity(b"").is_err());
        assert!(parse_identity(&hex.as_bytes()[..62]).is_err());
        assert!(parse_identity(format!("{hex}00").as_bytes()).is_err());
        assert!(parse_identity(&[b'z'; 64]).is_err());
    }

    /// **Write then read is the identity**, over a synthetic key and a block
    /// whose shards are shells.
    ///
    /// It verifies nothing and is not meant to: the property is that the four
    /// files carry the four values and each comes back through its own
    /// decoder. The real end-to-end path — a proved block written here and
    /// verified by the `verifier` binary from those files — is
    /// `tests/cli.rs::the_cli_verifies_a_block_file`, which is `#[ignore]`d
    /// because it proves a `2^20` statement. This is the fast test the root
    /// `CLAUDE.md` asks of a change whose only other cover is a deferred
    /// suite.
    #[test]
    fn a_written_proof_reads_back_as_itself() {
        let vk = crate::tests::key();
        let statement = PublicInputs {
            input: vec![1, 2, 3],
            output: vec![4, 5],
            exit_status: 0,
            shard_counts: vec![0, 1, 0, 1, 1, 0],
            windows: vec![],
            boundary: BoundaryFinals {
                reg_ts: [0; 32],
                pc_ts: 0,
                reg_values: [0; 31],
            },
            memory_commitments: vec![vec![], vec![], vec![]],
            memory_roots: vec![[field::Fr::ONE, field::Fr::ONE]; 3],
        };
        // Three shells, because `BlockProof::from_bytes` requires one proof,
        // one commitment list and one root pair per shard and the statement
        // above counts three — `INIT_TEARDOWN` and S-IO's two public windows,
        // which every statement carries.
        let shell = |family: u32| ShardProof {
            family,
            shard_index: 0,
            ts_window: [0, 0],
            global_digest: field::Fr::ZERO,
            witness_commitments: vec![],
            outputs: vec![],
            gkr: GkrProof { layers: vec![] },
            opening: [0; crate::OPENING_BYTES],
        };
        let block = BlockProof {
            config: vk.config.clone(),
            statement: statement.clone(),
            shards: vec![
                shell(constants::family::INIT_TEARDOWN),
                shell(constants::family::PUBLIC_INPUT),
                shell(constants::family::PUBLIC_OUTPUT),
            ],
        };

        // Keyed on the pid, which is what every temp directory in this
        // repository does: a fixed path is what made `fixture::build_guest`
        // unsafe to run twice at once, until it was keyed the same way.
        // `CARGO_TARGET_TMPDIR` is an integration-test variable and this is a
        // unit test, so it is not available here.
        let dir = std::env::temp_dir().join(format!("apogee-proof-archive-{}", std::process::id()));
        let paths = write_proof(&dir, "toy", &vk, &block).expect("the proof writes");
        assert_eq!(paths, ProofPaths::new(&dir, "toy"));

        let (vk2, id2, public2, block2) = read_proof(&dir, "toy").expect("it reads back");
        assert_eq!(vk2.to_bytes(), vk.to_bytes());
        assert_eq!(id2, vk.identity.to_bytes());
        assert_eq!(public2, statement);
        assert_eq!(block2.to_bytes(), block.to_bytes());

        // The statement file is the block's own, not a second copy a caller
        // chose: `write_proof` takes no statement argument, so the two cannot
        // disagree.
        assert_eq!(&public2, block2.statement());

        // A truncated file is named, not half-decoded.
        std::fs::write(&paths.block, b"short").unwrap();
        let e = read_proof(&dir, "toy").expect_err("a truncated block");
        assert!(e.contains("toy.block"), "{e}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
