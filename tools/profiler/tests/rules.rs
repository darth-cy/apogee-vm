//! The classification rules, held to what they are meant to say.
//!
//! The rules are an **ordered** list and the order is the semantics
//! (`docs/tools.md` §2.2), so the failure mode is a rule that a specific
//! one should have beaten and does not. Every case here is a symbol shape a
//! guest carries; one of them is a bug a real profile exposed, kept as a
//! regression.

use profiler::categories::{classify, Category, FALLBACK_RULES, RULES};
use profiler::demangle::demangle;

/// Each (raw symbol, the category it must land in). The raw name is what a real
/// ELF carries, and `classify` reads both it and the demangled path.
const CASES: [(&str, Category); 9] = [
    // A v0 name the partial decoder read badly. Matching the raw name too is
    // what puts it where it belongs.
    (
        "_RNvNtCsxJ7lp9_17compiler_builtins3mem6memcpy",
        Category::MemoryCopy,
    ),
    // `compiler_builtins` is the runtime, and the memcpy inside it is not.
    (
        "_ZN17compiler_builtins3mem6memset17h1111111111111111E",
        Category::MemoryCopy,
    ),
    ("memcpy", Category::MemoryCopy),
    (
        "_ZN4core3ptr19copy_nonoverlapping17h2222222222222222E",
        Category::MemoryCopy,
    ),
    (
        "_ZN5alloc3vec12Vec$LT$T$GT$4push17h3333333333333333E",
        Category::Alloc,
    ),
    ("__udivdi3", Category::CoreRuntime),
    (
        "_ZN9guest_sdk6commit17h4444444444444444E",
        Category::CoreRuntime,
    ),
    // --- and nothing claims a guest's own code ------------------------------
    ("_start", Category::Other),
    ("_ZN3fib4main17h5555555555555555E", Category::Other),
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
