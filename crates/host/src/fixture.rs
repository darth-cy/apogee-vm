//! What a recorded block is on disk, and how it is pinned.
//!
//! S25's must-be-exact 4: *"Fixtures are pinned by hash and committed, and CI
//! never touches RPC. Freshness = a manual refresh command that re-records and
//! re-pins."* A fixture is therefore three things:
//!
//! | file | what |
//! | --- | --- |
//! | `<name>.json` | this [`Pin`]: what block it is, and the SHA-256 of the other two |
//! | `<name>-witness.bin` | the `BlockWitness`, `postcard`, the guest's advice |
//! | `<name>-journal.bin` | what the guest publishes, as native revm computes it |
//!
//! Beside them sits `rpc-cache/`, the content-addressed snapshot of every
//! JSON-RPC response the recording read. The cache is what makes the
//! determinism test (acceptance 1) a test rather than a network round trip: a
//! second recording answers every request from disk and must produce the same
//! bytes.
//!
//! # What is committed, and what is not
//!
//! The mini-block fixture is committed whole — witness, journal, pin and cache.
//! It is a few kilobytes.
//!
//! The **full block's witness is not committed**, and its cache is not either.
//! A stateless mainnet block carries every touched account, every touched slot,
//! every contract's code and the Merkle-Patricia nodes authenticating all of
//! it; that is megabytes, and the RPC snapshot behind it is larger still. What
//! is committed is this `Pin` — the block, the roots, and the SHA-256 the
//! witness must have. That is the repository's existing answer for an artifact
//! too large to carry: `tools/kat-gen/src/delegation.rs` commits the three
//! delegation circuits *by digest* for the same reason, the artifacts being
//! megabytes. A digest file is still "pinned by hash and committed"; what it
//! costs is that regenerating the full block needs the network, which is why
//! that fixture's tests are `#[ignore]`d and skip when the witness is absent.

use serde::{Deserialize, Serialize};

/// Which guest binary a fixture is for, and therefore what it claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// The first few transactions of a real block against the real pre-state,
    /// with **no state-root claim**: the state the execution leaves is not the
    /// block's post-state, because the rest of the block did not run.
    Mini,
    /// The whole block transition — pre-block system calls, every transaction,
    /// withdrawals — with the pre-state authenticated against the parent's
    /// state root and the post-state root recomputed and checked against the
    /// header's.
    Stateless,
}

impl Mode {
    /// The guest binary that proves this mode.
    pub fn binary(self) -> &'static str {
        match self {
            Mode::Mini => "revm-block",
            Mode::Stateless => "revm-block-stateless",
        }
    }
}

/// A recorded block, by identity and by hash.
///
/// Everything here is a *claim about the chain* that a reader can check for
/// themselves against a node: the block number and hash name the block, and the
/// roots are the header's. Nothing here is derived from the witness except the
/// two digests, which are what pin it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    /// `mini` or `stateless`.
    pub mode: Mode,
    /// The block whose transactions were executed.
    pub block_number: u64,
    /// Its header hash, `0x`-prefixed.
    pub block_hash: String,
    /// Its parent's header hash.
    pub parent_hash: String,
    /// The parent's state root: what a stateless pre-state authenticates
    /// against, and what the recorded values were read at.
    pub parent_state_root: String,
    /// This block's state root, from the header: what the stateless mode's
    /// recomputation must equal.
    pub state_root: String,
    /// The hardfork, as `revm`'s `SpecId` discriminant.
    pub spec_id: u8,
    /// How many of the block's transactions were recorded. Equal to the
    /// header's transaction count in [`Mode::Stateless`], and 1 or 2 in
    /// [`Mode::Mini`].
    pub txs_recorded: usize,
    /// How many transactions the block has.
    pub txs_in_block: usize,
    /// Gas the recorded transactions used.
    pub gas_used: u64,
    /// Accounts in the witness.
    pub accounts: usize,
    /// Storage slots in the witness, over all accounts.
    pub slots: usize,
    /// The witness's length in bytes.
    pub witness_bytes: usize,
    /// SHA-256 of the witness file, lowercase hex.
    pub witness_sha256: String,
    /// The journal's length in bytes.
    pub journal_bytes: usize,
    /// SHA-256 of the journal file, lowercase hex.
    pub journal_sha256: String,
}

impl Pin {
    /// This pin as the committed JSON file's bytes.
    ///
    /// Pretty-printed with a trailing newline, so that a refresh shows up in a
    /// diff as the fields that moved rather than as one line.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut text = serde_json::to_string_pretty(self).expect("a Pin encodes");
        text.push('\n');
        text.into_bytes()
    }

    /// Those bytes back.
    pub fn from_bytes(bytes: &[u8]) -> Result<Pin, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("the pin does not decode: {e}"))
    }

    /// `Ok` when `witness` and `journal` are the bytes this pin names.
    pub fn check(&self, witness: &[u8], journal: &[u8]) -> Result<(), String> {
        check_one("witness", witness, self.witness_bytes, &self.witness_sha256)?;
        check_one("journal", journal, self.journal_bytes, &self.journal_sha256)
    }
}

fn check_one(what: &str, bytes: &[u8], len: usize, sha: &str) -> Result<(), String> {
    if bytes.len() != len {
        return Err(format!(
            "the {what} is {} bytes where the pin says {len}",
            bytes.len()
        ));
    }
    let actual = test_support::to_hex(&test_support::sha256(bytes));
    if actual != sha {
        return Err(format!(
            "the {what} hashes to {actual} where the pin says {sha}"
        ));
    }
    Ok(())
}

/// The three file names of a fixture, given its stem.
pub fn pin_file(stem: &str) -> String {
    format!("{stem}.json")
}

/// The witness file's name.
pub fn witness_file(stem: &str) -> String {
    format!("{stem}-witness.bin")
}

/// The journal file's name.
pub fn journal_file(stem: &str) -> String {
    format!("{stem}-journal.bin")
}

// ---------------------------------------------------------------------------
// The revm guest, built from source
// ---------------------------------------------------------------------------

/// The `ProgramParams` the revm guest is proved at: every family at the height
/// its **release** image needs, and each delegation family at its own default.
///
/// A decoded table's rows are absolute pcs, one per halfword, so a family's
/// height has to reach past the last instruction — `revm_block::
/// TRACE_HEIGHT_RELEASE` is that height, pinned beside the guest. A delegation
/// family claims no pc and is not bound by it (`docs/spec/delegation.md` §1), so
/// each keeps `constants::family::DEFAULT_HEIGHTS`' `2^8`.
pub fn revm_params() -> program::ProgramParams {
    let mut heights = [revm_block::TRACE_HEIGHT_RELEASE; constants::family::COUNT as usize];
    for (f, h) in heights.iter_mut().enumerate() {
        if program::delegation_ecall(f as u32).is_some() {
            *h = constants::family::DEFAULT_HEIGHTS[f];
        }
    }
    program::ProgramParams {
        heights,
        bytecode_size_words: revm_block::BYTECODE_SIZE_WORDS,
        ..program::ProgramParams::defaults()
    }
}

/// The revm guest binary for `mode`, built from source at `--release`.
///
/// **Always `--release`, whatever `APOGEE_GUEST_PROFILE` says**, for the reason
/// `crates/prover/tests/revm.rs` gives: [`revm_params`]'s heights are pinned to
/// the release image, and the debug image needs `2^22` — four times the rows in
/// every shard, for a build nothing proves.
///
/// It builds in a scratch target directory of its own and removes it, and it
/// clears every environment variable that would otherwise leak the host's build
/// configuration into a `riscv32imac` build. There is no committed ELF for this
/// guest (root `CLAUDE.md`), so building it is the only way to have it.
pub fn build_revm_guest(mode: Mode) -> Result<Vec<u8>, String> {
    let bin = mode.binary();
    let guest_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guests/revm-block");
    let target_dir = std::env::temp_dir().join(format!("apogee-guest-{bin}"));
    let _ = std::fs::remove_dir_all(&target_dir);
    let mut command =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(&guest_dir)
        .args([
            "build",
            "--release",
            "--target",
            "riscv32imac-unknown-none-elf",
            "--bin",
            bin,
        ])
        .env("CARGO_TARGET_DIR", &target_dir);
    for key in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        command.env_remove(key);
    }
    let out = command
        .output()
        .map_err(|e| format!("running cargo for {bin}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{bin}: guest build failed\n{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let elf = target_dir
        .join("riscv32imac-unknown-none-elf/release")
        .join(bin);
    let bytes = std::fs::read(&elf).map_err(|e| format!("reading {}: {e}", elf.display()))?;
    let _ = std::fs::remove_dir_all(&target_dir);
    Ok(bytes)
}
