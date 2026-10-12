//! What a symbol *is*: the classification rules that turn a function name into
//! a workload.
//!
//! `docs/tools.md` §2.2 is the design. The rules are an **ordered** list
//! of substring patterns, first match winning, so the specific ones come before
//! the general: `compiler_builtins::mem::memcpy` is memory copy and
//! `compiler_builtins` is the runtime, and the order is what says which. They
//! are matched against the demangled path, which for both mangling schemes
//! contains the crate and module names literally.
//!
//! Adding a rule is adding a line. What must not happen is a rule that overlaps
//! an earlier one and was meant to win: `tests/rules.rs` holds every pattern to
//! the category it is meant to give and checks that no earlier pattern shadows
//! it.

use serde::{Deserialize, Serialize};

/// A workload. Every function of a guest lands in exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Category {
    /// `memcpy`, `memmove`, `memset` and the pointer primitives under them.
    MemoryCopy,
    /// The guest's allocator, and `alloc`'s containers.
    Alloc,
    /// `core`, `compiler_builtins` and the guest SDK: 64-bit division helpers,
    /// formatting, slice primitives, panic machinery, the entry point and the
    /// I/O calls.
    CoreRuntime,
    /// A symbol no rule claims — the guest's own code — and a pc no symbol
    /// claims.
    Other,
}

impl Category {
    pub fn name(self) -> &'static str {
        match self {
            Category::MemoryCopy => "memory copy",
            Category::Alloc => "allocation",
            Category::CoreRuntime => "core runtime",
            Category::Other => "unattributed",
        }
    }

    /// Every category, in report order.
    pub const ALL: [Category; 4] = [
        Category::MemoryCopy,
        Category::Alloc,
        Category::CoreRuntime,
        Category::Other,
    ];
}

/// The rules, in order. First match wins.
///
/// Each pattern is a substring of the demangled path. The order is the whole of
/// the semantics.
pub const RULES: [(&str, Category); 4] = [
    ("memcpy", Category::MemoryCopy),
    ("memmove", Category::MemoryCopy),
    ("memset", Category::MemoryCopy),
    ("memcmp", Category::MemoryCopy),
];

/// The rules that only apply after every rule above has missed: the generic
/// runtime ones, which would otherwise swallow a path that a specific rule
/// should have claimed (`compiler_builtins::mem::memcpy`, say).
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
/// misclassify a name the decoder reads badly, `compiler_builtins::mem::memcpy`
/// among them.
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
