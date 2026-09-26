//! What a symbol *is*, semantically: the classification rules that turn a
//! function name into a workload an accelerator could replace.
//!
//! `docs/spec/profiling.md` §3 is the design. The rules are an **ordered** list
//! of substring patterns, first match winning, so the specific ones come before
//! the general: `revm_interpreter::instructions::system::keccak256` is hashing
//! and `revm_interpreter::` is interpreter overhead, and the order is what says
//! which. They are matched against the demangled path, which for both mangling
//! schemes contains the crate and module names literally.
//!
//! Adding a rule is adding a line. What must not happen is a rule that overlaps
//! an earlier one and was meant to win: `tests/rules.rs` holds every pattern to
//! the category it is meant to give and checks that no earlier pattern shadows
//! it.

use serde::{Deserialize, Serialize};

/// A semantic workload. Every function of a guest lands in exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Category {
    /// `keccak256`, wherever it is computed — including the S21 shim.
    Keccak,
    /// SHA-256 and RIPEMD-160: the EVM's other two hash precompiles.
    OtherHash,
    /// secp256k1: `ecrecover`, one per transaction and per `0x01` call.
    Secp256k1,
    /// BN254 pairing and curve arithmetic: the `0x06`–`0x08` precompiles.
    Bn254,
    /// **256-bit arithmetic**: the EVM's arithmetic and comparison opcodes, and
    /// `ruint`'s wide integers wherever they are not inlined into them.
    U256Arith,
    /// The interpreter itself: dispatch, the stack, gas accounting, memory
    /// opcodes, control flow.
    Interpreter,
    /// The EVM's state layer: account and storage access, the journal, the
    /// context, and the host's own bookkeeping.
    EvmState,
    /// `memcpy`, `memmove`, `memset` and the pointer primitives under them.
    MemoryCopy,
    /// The guest's allocator, and `alloc`'s containers.
    Alloc,
    /// RLP encoding and the Merkle-Patricia trie.
    RlpTrie,
    /// This VM's own delegation **shims**: the frame's stores, the ecall, the
    /// results' loads. What a delegated operation costs the guest.
    ///
    /// It is deliberately NOT "the work the delegations replace": the keccak
    /// sponge around the delegated permutation is `keccak256` work and is
    /// counted there, because a category called "already delegated" that held it
    /// would hide 4% of a real block behind a reassuring name. The answer to
    /// "the existing delegations against ordinary RV32 execution" is the
    /// **family** invocation counts beside these cycles.
    Delegated,
    /// Decoding the block witness, and the guest's own block executor.
    BlockSetup,
    /// `core` and `compiler_builtins`: 64-bit division helpers, formatting,
    /// slice primitives, panic machinery.
    CoreRuntime,
    /// A symbol no rule claims, and a pc no symbol claims.
    Other,
}

impl Category {
    pub fn name(self) -> &'static str {
        match self {
            Category::Keccak => "keccak256",
            Category::OtherHash => "sha256/ripemd160",
            Category::Secp256k1 => "secp256k1",
            Category::Bn254 => "bn254",
            Category::U256Arith => "256-bit arithmetic",
            Category::Interpreter => "evm interpreter",
            Category::EvmState => "evm state + journal",
            Category::MemoryCopy => "memory copy",
            Category::Alloc => "allocation",
            Category::RlpTrie => "rlp + trie",
            Category::Delegated => "delegation shims",
            Category::BlockSetup => "witness + block setup",
            Category::CoreRuntime => "core runtime",
            Category::Other => "unattributed",
        }
    }

    /// Every category, in report order.
    pub const ALL: [Category; 14] = [
        Category::Keccak,
        Category::OtherHash,
        Category::Secp256k1,
        Category::Bn254,
        Category::U256Arith,
        Category::Interpreter,
        Category::EvmState,
        Category::MemoryCopy,
        Category::Alloc,
        Category::RlpTrie,
        Category::Delegated,
        Category::BlockSetup,
        Category::CoreRuntime,
        Category::Other,
    ];
}

/// The rules, in order. First match wins.
///
/// Each pattern is a substring of the demangled path. The comments say why a
/// rule is where it is; the order is the whole of the semantics.
pub const RULES: [(&str, Category); 53] = [
    // --- the delegation shims, before anything else -----------------------
    // `guest_sdk::recursion` is S23's two shims, and `recursion` rather than
    // the full path because a partially decoded v0 name has no `::` in it
    // (`crate::demangle`). The keccak SHIM is not here: it is the sponge, which
    // is keccak work, and the rule below claims it.
    ("recursion", Category::Delegated),
    // --- hashing ----------------------------------------------------------
    ("keccak", Category::Keccak),
    ("native_keccak256", Category::Keccak),
    ("Keccak", Category::Keccak),
    ("tiny_keccak", Category::Keccak),
    ("sha2::", Category::OtherHash),
    ("sha256", Category::OtherHash),
    ("Sha256", Category::OtherHash),
    ("ripemd", Category::OtherHash),
    ("Ripemd", Category::OtherHash),
    // --- elliptic curves --------------------------------------------------
    ("k256", Category::Secp256k1),
    ("secp256k1", Category::Secp256k1),
    ("ecrecover", Category::Secp256k1),
    ("ec_recover", Category::Secp256k1),
    ("elliptic_curve", Category::Secp256k1),
    ("p256", Category::Secp256k1),
    ("bn128", Category::Bn254),
    ("bn254", Category::Bn254),
    ("ark_bn254", Category::Bn254),
    ("ark_ec", Category::Bn254),
    ("ark_ff", Category::Bn254),
    // --- 256-bit arithmetic ------------------------------------------------
    // The EVM's arithmetic and comparison opcode handlers. `ruint`'s wide
    // integers are mostly inlined INTO these, which is why the opcode handler
    // is the unit this category counts (`docs/spec/profiling.md` §3.1).
    ("instructions::arithmetic", Category::U256Arith),
    ("instructions::bitwise", Category::U256Arith),
    ("ruint", Category::U256Arith),
    ("Uint::", Category::U256Arith),
    ("U256", Category::U256Arith),
    // --- rlp and the trie -------------------------------------------------
    ("alloy_rlp", Category::RlpTrie),
    ("::rlp", Category::RlpTrie),
    ("mpt::", Category::RlpTrie),
    ("trie", Category::RlpTrie),
    // --- the block's own setup --------------------------------------------
    // `serde` and `postcard` are here and not under the runtime because in this
    // guest they do exactly one thing: decode the block witness and, for the
    // canonicity rule, re-encode it (`docs/spec/revm-block.md` §1.1). They must
    // also come before the `core::` fallback, which `serde_core::` contains as a
    // substring -- the bug this rule was added to fix.
    ("serde", Category::BlockSetup),
    ("postcard", Category::BlockSetup),
    ("BlockWitness", Category::BlockSetup),
    ("WitnessDb", Category::BlockSetup),
    ("revm_block", Category::BlockSetup),
    // --- the EVM's state layer --------------------------------------------
    ("instructions::host", Category::EvmState),
    ("instructions::contract", Category::EvmState),
    ("revm_state", Category::EvmState),
    ("revm_database", Category::EvmState),
    ("revm_context", Category::EvmState),
    ("revm_handler", Category::EvmState),
    ("journal", Category::EvmState),
    ("Journal", Category::EvmState),
    // --- the interpreter, after every specific revm rule ------------------
    ("revm_interpreter", Category::Interpreter),
    ("revm_precompile", Category::Interpreter),
    // Jump-destination analysis: the interpreter's own setup for a contract.
    ("revm_bytecode", Category::Interpreter),
    ("revm_primitives", Category::Interpreter),
    ("alloy_primitives", Category::Interpreter),
    ("revm", Category::Interpreter),
    // --- the runtime ------------------------------------------------------
    ("memcpy", Category::MemoryCopy),
    ("memmove", Category::MemoryCopy),
    ("memset", Category::MemoryCopy),
    ("memcmp", Category::MemoryCopy),
];

/// The rules that only apply after every rule above has missed: the generic
/// runtime ones, which would otherwise swallow a `core::` path that a specific
/// rule should have claimed (`alloc::vec::Vec::<ruint::Uint>::push`, say).
pub const FALLBACK_RULES: [(&str, Category); 9] = [
    ("core::ptr", Category::MemoryCopy),
    ("core::slice", Category::MemoryCopy),
    ("alloc::", Category::Alloc),
    ("guest_sdk::alloc", Category::Alloc),
    ("__rust_alloc", Category::Alloc),
    ("core::", Category::CoreRuntime),
    ("compiler_builtins", Category::CoreRuntime),
    // The SDK's other parts: crt0, `entry!`, `exit`, `commit`, `advice`.
    ("guest_sdk", Category::CoreRuntime),
    ("__", Category::CoreRuntime),
];

/// Which category a symbol belongs to, from its demangled path **and** its raw
/// mangled name.
///
/// Both, because a crate and module name appears literally in both mangling
/// schemes and the v0 decoder is deliberately partial
/// (`crate::demangle`): a rule that matched only the decoded path would
/// misclassify a name the decoder read badly, which is exactly what
/// `compiler_builtins::mem::memcpy` did before this took the raw name too.
pub fn classify(path: &str, raw: &str) -> Category {
    let hit = |pattern: &str| path.contains(pattern) || raw.contains(pattern);
    for (pattern, category) in RULES {
        if hit(pattern) {
            return category;
        }
    }
    for (pattern, category) in FALLBACK_RULES {
        if hit(pattern) {
            return category;
        }
    }
    Category::Other
}

/// A candidate accelerator: the category it would remove, the symbols whose
/// **calls** are its entry points, and the frame it would pass.
///
/// `removable = cycles − calls · (4 + 2·frame_words)`: every guest cycle in the
/// category goes, and what stays is the shim — the frame's stores, the ecall,
/// and the results' loads (`docs/spec/profiling.md` §4).
pub struct Candidate {
    pub category: Category,
    /// Substrings of the demangled path whose **entry** cycle count is a call
    /// into the candidate. Empty means the call count is unknown, and then the
    /// removable figure is the category's whole cycle count with no shim charged
    /// — a ceiling the report labels as such.
    pub entries: &'static [&'static str],
    /// The frame the delegation would take, in 32-bit words.
    pub frame_words: u32,
}

/// The candidates this profiler prices, and what each would cost per call.
///
/// The frame widths are the shapes `docs/spec/delegation.md` §4 allows: a
/// delegation reads and writes one contiguous block of guest memory at fixed
/// offsets, so the width is the operands plus the results.
pub const CANDIDATES: [Candidate; 5] = [
    Candidate {
        category: Category::Secp256k1,
        // One `ecrecover` per transaction signature and per `0x01` call.
        entries: &["ec_recover", "ecrecover", "recover_verify_key"],
        // 32-byte hash, 64-byte signature, recovery id, 20-byte address out.
        //
        // This is the **ceiling** and it models a whole-`ecrecover` delegation,
        // which is not what S26 built: `MOD_MUL` replaces the field *multiply*
        // inside it, one call per multiply over a 32-word frame, and S22's
        // cancellation rules out a family that verifies a signature. What that
        // actually removed, measured, is 54% of this category on S26's pinned
        // mini-block (`docs/handoff/S26-cycle.md` §6.2) — the rest being the
        // ladder's bookkeeping, `conditional_select` and `memcpy`. So the figure
        // below stays a ceiling and is labelled one; it is not a prediction.
        frame_words: 8 + 16 + 1 + 5,
    },
    Candidate {
        category: Category::U256Arith,
        // No single entry: the arithmetic is inlined into 27 opcode handlers,
        // so this one's figure is a ceiling with no shim charged.
        entries: &[],
        // Two 256-bit operands, a 256-bit modulus, a 256-bit result.
        frame_words: 8 * 4,
    },
    Candidate {
        category: Category::Bn254,
        entries: &["bn128", "run_pair", "run_add", "run_mul"],
        frame_words: 8 * 8,
    },
    Candidate {
        category: Category::OtherHash,
        entries: &["sha256_run", "ripemd160_run", "compress256"],
        // One 64-byte block in, eight words of state.
        frame_words: 16 + 8,
    },
    Candidate {
        category: Category::Keccak,
        // The permutation is already delegated. What is left in this category is
        // the **sponge** -- padding, the rate's byte order, the absorb and
        // squeeze loops -- which is the number this candidate exists to
        // surface, and a wider frame is what would remove it.
        entries: &["keccak256"],
        frame_words: 50,
    },
];

/// The modelled cost of one delegation call: the frame's stores, the ecall, and
/// the results' loads.
pub fn shim_cycles(frame_words: u32) -> u64 {
    4 + 2 * frame_words as u64
}
