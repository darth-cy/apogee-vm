//! The classification rules, held to what they are meant to say.
//!
//! The rules are an **ordered** list and the order is the semantics
//! (`docs/spec/profiling.md` §3), so the failure mode is a rule that a specific
//! one should have beaten and does not. Every case here is a real symbol from
//! `guests/revm-block`, or a shape the guest's own source has; two of them are
//! bugs a profile of the pinned mini-block exposed, kept as regressions.

use profiler::categories::{classify, Category, FALLBACK_RULES, RULES};
use profiler::demangle::demangle;

/// Each (raw symbol, the category it must land in). The raw name is what a real
/// ELF carries, and `classify` reads both it and the demangled path.
const CASES: [(&str, Category); 26] = [
    // --- the two bugs the mini-block profile exposed ----------------------
    // `serde_core::` contains `core::`, so the CoreRuntime fallback claimed
    // 13.6% of a block's cycles that are the WITNESS DECODE.
    (
        "_ZN11serde_core2de9SeqAccess12next_element17h1111111111111111E",
        Category::BlockSetup,
    ),
    // A v0 name the partial decoder read badly. Matching the raw name too is
    // what puts it where it belongs.
    (
        "_RNvNtCsxJ7lp9_17compiler_builtins3mem6memcpy",
        Category::MemoryCopy,
    ),
    // --- the workload that dominates a real block -------------------------
    (
        "_ZN4k2564arith5field10field_impl16FieldElementImpl3mul17h2222222222222222E",
        Category::Secp256k1,
    ),
    (
        "_ZN4k2564arith6scalar6Scalar3mul17h3333333333333333E",
        Category::Secp256k1,
    ),
    (
        "_ZN15revm_precompile11secp256k110ec_recover17h4444444444444444E",
        Category::Secp256k1,
    ),
    // --- hashing ----------------------------------------------------------
    ("native_keccak256", Category::Keccak),
    // The keccak shim is the SPONGE around the delegated permutation, so it is
    // keccak work and not a delegation's cost.
    (
        "_ZN9guest_sdk9keccak25617h5555555555555555E",
        Category::Keccak,
    ),
    (
        "_ZN9guest_sdk9recursion17poseidon2_permute17h6666666666666666E",
        Category::Delegated,
    ),
    (
        "_ZN11tiny_keccak8keccakf17h7777777777777777E",
        Category::Keccak,
    ),
    (
        "_ZN15revm_precompile6hash6sha25617h8888888888888888E",
        Category::OtherHash,
    ),
    (
        "_ZN6ripemd4core8compress17h9999999999999999E",
        Category::OtherHash,
    ),
    // --- curves -----------------------------------------------------------
    (
        "_ZN15revm_precompile5bn1288run_pair17haaaaaaaaaaaaaaaaE",
        Category::Bn254,
    ),
    (
        "_ZN9ark_bn2545curves1g113G1Projective3add17hbbbbbbbbbbbbbbbbE",
        Category::Bn254,
    ),
    // --- 256-bit arithmetic ------------------------------------------------
    (
        "_ZN16revm_interpreter12instructions10arithmetic3mul17hccccccccccccccccE",
        Category::U256Arith,
    ),
    (
        "_ZN16revm_interpreter12instructions7bitwise3and17hddddddddddddddddE",
        Category::U256Arith,
    ),
    (
        "_ZN5ruint10algorithms3div17heeeeeeeeeeeeeeeeE",
        Category::U256Arith,
    ),
    // --- the interpreter, only after every specific revm rule -------------
    (
        "_ZN16revm_interpreter11interpreter5stack5Stack4push17hffffffffffffffffE",
        Category::Interpreter,
    ),
    (
        "_ZN13revm_bytecode6legacy8analysis14analyze_legacy17h0000000000000001E",
        Category::Interpreter,
    ),
    (
        "_ZN16revm_interpreter12instructions4host6sstore17h0000000000000002E",
        Category::EvmState,
    ),
    (
        "_ZN12revm_context7journal12JournalInner5touch17h0000000000000003E",
        Category::EvmState,
    ),
    // --- rlp and the trie -------------------------------------------------
    (
        "_ZN9alloy_rlp6encode6Encodable17h0000000000000004E",
        Category::RlpTrie,
    ),
    (
        "_ZN10revm_block3mpt4Trie4root17h0000000000000005E",
        Category::RlpTrie,
    ),
    // --- the runtime ------------------------------------------------------
    ("memcpy", Category::MemoryCopy),
    (
        "_ZN5alloc3vec12Vec$LT$T$GT$4push17h0000000000000006E",
        Category::Alloc,
    ),
    ("__udivdi3", Category::CoreRuntime),
    // --- and nothing claims a guest's own entry point ----------------------
    ("_start", Category::Other),
];

#[test]
fn every_rule_says_what_it_is_meant_to_say() {
    for (raw, want) in CASES {
        let path = demangle(raw);
        let got = classify(&path, raw);
        assert_eq!(
            got, want,
            "{raw}\n  demangled to {path}\n  classified {got:?}"
        );
    }
}

/// A pattern that an earlier pattern already contains is dead: the earlier one
/// wins on every string the later one matches, so the later rule can never fire
/// and its category is a lie about the code.
///
/// The exception is a pattern that means the same thing as the one that shadows
/// it, which the table has none of.
#[test]
fn no_rule_is_shadowed_by_an_earlier_one() {
    let all: Vec<(&str, Category)> = RULES.iter().chain(FALLBACK_RULES.iter()).copied().collect();
    for (i, (pattern, category)) in all.iter().enumerate() {
        for (earlier, other) in &all[..i] {
            assert!(
                !pattern.contains(earlier) || other == category,
                "`{pattern}` ({category:?}) can never fire: `{earlier}` ({other:?}) comes first \
                 and every string holding `{pattern}` holds `{earlier}`"
            );
        }
    }
}

/// Every category is reachable. A category with no rule is a column of zeros in
/// every report, which reads as "the workload does none of this" rather than
/// "nothing can ever land here".
#[test]
fn every_category_but_other_has_a_rule() {
    for category in Category::ALL {
        if category == Category::Other {
            continue;
        }
        assert!(
            RULES
                .iter()
                .chain(FALLBACK_RULES.iter())
                .any(|(_, c)| *c == category),
            "{category:?} has no rule"
        );
    }
}
