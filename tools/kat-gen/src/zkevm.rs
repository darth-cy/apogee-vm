//! The `zkevm` group: a subset of a `tests-zkevm` release's stateless pairs,
//! committed so that CI holds the stateless guest to the spec's own outputs
//! without the release, which is 620 MB packed and 5.9 GB extracted.
//!
//!     APOGEE_ZKEVM_FIXTURES=/path/to/fixtures cargo run --release -p kat-gen -- zkevm
//!
//! **Opt-in, like `block` and `guests`**: it reads a release CI does not have.
//!
//! What is kept, each for a reason `crates/host/tests/conformance.rs` can
//! check — it holds every case to its output bytes *and* to the rule named
//! beside it:
//!
//! - for every rule the validator refuses by (`stateless::Invalid`'s variant,
//!   with its transaction index and any hash dropped), the smallest input the
//!   release refuses by it. Deleting that rule's check moves its case to a
//!   later rule or to `valid`.
//! - the smallest valid input, and every undecodable one, each a different way
//!   an SSZ body or its schema id is not a stateless input.
//! - by name, the cases that pin `docs/spec/ethereum.md` §4.4's three rules,
//!   each one where following reth gives a result other than the spec's: a
//!   validator without the rule refuses its case.
//!
//! A release appears twice over, as blockchain and as engine fixtures with the
//! same inputs; a case is kept once, under its first name. **The group refuses
//! to cut a subset from a release the validator does not match in full**, or
//! from another release than the one `host::zkevm::RELEASE_COMMIT` names: a
//! subset is evidence only of a whole that agrees.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use host::zkevm::{self, Pair, FIXTURES_VAR, RELEASE_COMMIT};
use serde_json::json;
use test_support::{sha256, to_hex};

/// Where the subset goes.
const SUBSET: &str = "crates/host/tests/vectors/zkevm-subset.json";

/// The largest input a case may be. The one rule this leaves without a case
/// is EIP-7934's block size, whose smallest refusal is 8 MiB by definition;
/// `crates/host/tests/canonical.rs` holds `block_rlp_len` to real blocks'
/// sizes instead.
const MAX_CASE_BYTES: usize = 1 << 16;

/// The cases that pin those rules, each named by its test and parameters.
const NAMED: [&str; 5] = [
    // A coinbase that is a contract no transaction calls: its code is not in
    // the witness, and a database that loads code with every account refuses
    // the block for it.
    "test_fill_stack[fork_Amsterdam-blockchain_test_from_state_test--g0]",
    // A deletion that collapses a branch before a write repopulates it, in a
    // storage trie and in the state trie: replayed in that order, the collapse
    // needs a sibling the spec's witness does not carry.
    "test_witness_state_delete_then_insert_uses_insert_before_delete_order[fork_Amsterdam-blockchain_test]",
    "test_witness_state_block_diff_delete_insert_before_delete_order[fork_Amsterdam-blockchain_test]",
    // A slot one post-execution call toggles and the next restores, and a
    // withdrawal a dequeue forwards on: netted per call, each is a write the
    // block access list does not have.
    "test_bal_post_execution_calls_net_storage_at_last_index[fork_Amsterdam-blockchain_test]",
    "test_bal_withdrawals_and_dequeues_net_balance_at_last_index[fork_Amsterdam-blockchain_test-forward_all]",
];

/// A rule's name: a verdict with its transaction index and any hash dropped,
/// so `Signature(3)` and `Signature(0)` are one rule.
fn rule_of(verdict: &str) -> String {
    let mut out = String::new();
    let mut chars = verdict.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ' ' && chars.peek() == Some(&'{') {
            let mut depth = 0;
            for c in chars.by_ref() {
                depth += (c == '{') as i32 - (c == '}') as i32;
                if depth == 0 {
                    break;
                }
            }
        } else if c == '(' && chars.peek().is_some_and(char::is_ascii_digit) {
            chars.by_ref().find(|c| *c == ')');
        } else {
            out.push(c);
        }
    }
    out
}

pub fn generate() {
    let dir = PathBuf::from(
        std::env::var(FIXTURES_VAR)
            .unwrap_or_else(|_| panic!("the zkevm group reads a release: set {FIXTURES_VAR}")),
    );
    let commit = zkevm::release_commit(&dir).expect("the release's .meta/fixtures.ini");
    assert_eq!(
        commit,
        RELEASE_COMMIT,
        "{} is not the release the stateless guest implements",
        dir.display()
    );

    let mut seen = BTreeSet::new();
    let mut oversized = BTreeSet::new();
    let mut smallest: BTreeMap<String, (String, String, Pair)> = BTreeMap::new();
    let mut kept = Vec::new();
    let mut total = 0;
    for path in zkevm::files(&dir) {
        let file = path
            .strip_prefix(&dir)
            .expect("under the release")
            .display()
            .to_string();
        for pair in zkevm::pairs(&path) {
            total += 1;
            let name = format!("{file}{}", pair.name);
            assert!(
                revm_block::stateless::run(&pair.input)[..] == pair.output[..],
                "the validator disagrees with the release on {name}: run tests/conformance.rs"
            );
            if !seen.insert(sha256(&pair.input)) {
                continue;
            }
            let verdict = zkevm::verdict(&pair.input);
            let rule = rule_of(&verdict);
            if pair.input.len() > MAX_CASE_BYTES {
                oversized.insert(rule);
            } else if rule == "undecodable" || NAMED.iter().any(|n| name.contains(n)) {
                kept.push((name, verdict, pair));
            } else if smallest
                .get(&rule)
                .is_none_or(|(_, _, best)| pair.input.len() < best.input.len())
            {
                smallest.insert(rule, (name, verdict, pair));
            }
        }
    }
    assert_eq!(
        kept.iter()
            .filter(|(_, verdict, _)| verdict != "undecodable")
            .count(),
        NAMED.len(),
        "a named case is missing from the release"
    );
    for rule in oversized
        .iter()
        .filter(|rule| !smallest.contains_key(*rule))
    {
        println!("no case of {rule} is under {MAX_CASE_BYTES} bytes");
    }
    kept.extend(smallest.into_values());
    kept.sort_by(|a, b| (rule_of(&a.1), &a.0).cmp(&(rule_of(&b.1), &b.0)));

    let cases: Vec<_> = kept
        .iter()
        .map(|(name, verdict, pair)| {
            json!({
                "name": name,
                "rule": verdict,
                "statelessInputBytes": format!("0x{}", to_hex(&pair.input)),
                "statelessOutputBytes": format!("0x{}", to_hex(&pair.output)),
            })
        })
        .collect();
    let subset = json!({ "commit": commit, "cases": cases });
    println!(
        "{total} pairs, {} distinct, all matching: {} kept",
        seen.len(),
        cases.len()
    );
    crate::write_vectors(
        SUBSET,
        &(serde_json::to_string_pretty(&subset).expect("JSON") + "\n"),
    );
}
