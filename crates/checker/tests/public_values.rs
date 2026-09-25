//! S-IO's public values and advice: the parts that can be checked without a
//! proof, and the negative control for each.
//!
//! The expensive half — a real statement, tampered, refused by class — is
//! `crates/prover/tests/public_io.rs`, `#[ignore]`d for size. What is here is
//! everything that does not need a proof, and it is deliberately the part that
//! carries the subtle claims: that the window layout is **injective on byte
//! strings**, that the prover's column and the verifier's extension are the
//! same vector, that the journal's family has no init column to pre-load, and
//! that each statement rule refuses what it is for.
//!
//! `docs/spec/public-values.md` is the page this file holds the code to.

mod common;

use common::{traced, HEIGHT};
use constants::{family, guest_memory};
use constraints::memory::{value_window_artifact, zero_window_artifact};
use constraints::PolyAddress;
use program::public_io_words;
use trace::{advice_region_words, advice_window_count, advice_word, build_value_window_columns};
use verifier_core::{advice_first_window, check_memory_windows, VmConfig};

// ---------------------------------------------------------------------------
// The layout
// ---------------------------------------------------------------------------

/// The window is the length word, the payload little-endian, then zeros —
/// `docs/spec/public-values.md` §3 — and it is exactly `PUBLIC_WINDOW_HEIGHT`
/// words however short the payload.
#[test]
fn a_public_window_is_its_length_word_then_its_payload() {
    let words = public_io_words(&[]);
    assert_eq!(words.len(), family::PUBLIC_WINDOW_HEIGHT as usize);
    assert!(
        words.iter().all(|w| *w == 0),
        "an empty payload is all zero"
    );

    let words = public_io_words(&[0xAA, 0xBB, 0xCC, 0xDD, 0x11]);
    assert_eq!(words[0], 5, "word 0 is the payload's byte length");
    assert_eq!(words[1], 0xDDCC_BBAA, "the payload is little-endian");
    assert_eq!(words[2], 0x0000_0011, "a partial word is zero-extended");
    assert!(words[3..].iter().all(|w| *w == 0), "and then zeros");
}

/// **The length word is what makes the binding exact.** Without it a payload
/// and the same payload with trailing zeros fill the same window, and both
/// would be honestly provable from one execution — the prover would pick
/// whichever suited it and the verifier could not tell them apart
/// (`docs/spec/public-values.md` §3).
///
/// The control is the same pairs with the length word struck out: every one of
/// them collides, which is what the word is buying.
#[test]
fn the_length_word_separates_a_payload_from_its_zero_extension() {
    let bodies: [&[u8]; 5] = [&[], &[1], &[1, 2, 3], &[1, 2, 3, 4], &[0, 0, 0]];
    for body in bodies {
        let mut extended = body.to_vec();
        extended.push(0);
        assert_ne!(
            public_io_words(body),
            public_io_words(&extended),
            "{body:?} and {body:?} ‖ 0x00 fill the same window"
        );
        // The control: drop the length word and they do collide, whenever the
        // extension does not cross a word boundary.
        if !body.len().is_multiple_of(4) {
            assert_eq!(
                public_io_words(body)[1..],
                public_io_words(&extended)[1..],
                "{body:?}: the payload words alone do not separate them"
            );
        }
    }
}

/// Distinct payloads fill distinct windows, over every length the exhaustive
/// check can afford: the layout is injective, so the extension the verifier
/// evaluates names one byte string and not a class of them.
#[test]
fn distinct_payloads_fill_distinct_windows() {
    // Every byte string of length 0 to 4 over `{0, 1, 2}`: 121 of them, which
    // covers the empty payload, both sides of a word boundary, and the trailing
    // zero that the length word is there for.
    let mut payloads: Vec<Vec<u8>> = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..4 {
        let mut next = Vec::new();
        for base in &frontier {
            for byte in 0..3u8 {
                let mut p = base.clone();
                p.push(byte);
                next.push(p);
            }
        }
        payloads.extend(next.iter().cloned());
        frontier = next;
    }
    assert_eq!(payloads.len(), 121);

    let mut seen = std::collections::HashMap::new();
    for payload in payloads {
        let words = public_io_words(&payload);
        if let Some(other) = seen.insert(words, payload.clone()) {
            panic!("{payload:?} and {other:?} fill the same window");
        }
    }
}

/// A payload above the window's capacity is a caller error and panics: the
/// verifier refuses such a statement as `Statement` in `derive_global_phase`
/// before it ever asks for the layout.
#[test]
#[should_panic(expected = "a public window carries at most")]
fn a_payload_above_the_window_panics() {
    public_io_words(&vec![0u8; guest_memory::PUBLIC_PAYLOAD_BYTES as usize + 1]);
}

/// The advice region is its length word then its payload, **and no advice
/// means no region at all** — otherwise every program would pay one
/// `ADVICE_WINDOWS` shard to say it has none
/// (`docs/spec/public-values.md` §6).
#[test]
fn the_advice_region_is_a_length_word_then_a_payload() {
    assert_eq!(advice_region_words(&[]), 0);
    assert_eq!(advice_window_count(&[], HEIGHT), 0);

    let advice = [0xAAu8, 0xBB, 0xCC, 0xDD, 0x11];
    assert_eq!(
        advice_region_words(&advice),
        3,
        "a length word and two words"
    );
    assert_eq!(advice_word(&advice, 0), 5, "word 0 is the byte length");
    assert_eq!(advice_word(&advice, 1), 0xDDCC_BBAA);
    assert_eq!(advice_word(&advice, 2), 0x0000_0011);
    assert_eq!(advice_word(&advice, 3), 0, "and zero past the end");
    assert_eq!(advice_window_count(&advice, HEIGHT), 1);

    // Exactly one window's worth, and one byte more.
    let full = vec![7u8; 4 * (HEIGHT as usize - 1)];
    assert_eq!(advice_region_words(&full), HEIGHT as u64);
    assert_eq!(advice_window_count(&full, HEIGHT), 1);
    let over = vec![7u8; 4 * (HEIGHT as usize - 1) + 1];
    assert_eq!(advice_window_count(&over, HEIGHT), 2);
}

// ---------------------------------------------------------------------------
// The prover's column and the verifier's extension are one vector
// ---------------------------------------------------------------------------

/// `trace::build_value_window_columns` writes `M[2]` exactly as
/// `public_io_words` lays the window out.
///
/// This is the seam step 10c rests on: the verifier evaluates its own
/// extension of `public_io_words(public.input)` and compares it with the
/// committed column, so if the two ever disagreed about the layout every
/// honest proof would be refused — and, worse, a *changed* layout on one side
/// alone would be a soundness hole rather than a build failure.
#[test]
fn the_input_window_column_is_the_verifiers_own_layout() {
    let t = traced("fib", 24);
    let words = public_io_words(&t.input);
    let columns = build_value_window_columns(
        &t.log,
        &words,
        family::PUBLIC_INPUT_WINDOW,
        family::PUBLIC_WINDOW_HEIGHT as usize,
    );
    let init = columns
        .iter()
        .find(|(a, _)| *a == PolyAddress::Memory(2))
        .map(|(_, c)| c)
        .expect("a value window commits M[2]");
    assert_eq!(init.len(), words.len());
    for (y, want) in words.iter().enumerate() {
        assert_eq!(
            init.get(y),
            field::Fr::from_u64(*want as u64),
            "row {y} of the init column"
        );
    }

    // `fib` never touches the window, so its teardown is its init and the two
    // tuples cancel: the family costs a program that ignores public values
    // nothing but its two shards.
    let teardown = columns
        .iter()
        .find(|(a, _)| *a == PolyAddress::Memory(1))
        .map(|(_, c)| c)
        .expect("a value window commits M[1]");
    for y in 0..words.len() {
        assert_eq!(teardown.get(y), init.get(y), "row {y} is untouched");
    }
}

// ---------------------------------------------------------------------------
// The journal cannot be pre-loaded
// ---------------------------------------------------------------------------

/// **`PUBLIC_OUTPUT`'s circuit is `ZERO_WINDOWS`', byte for byte**, and that is
/// the whole of why a prover cannot supply the journal at timestamp 0 instead
/// of storing it: the family has no init column to put it in.
///
/// If this ever fails because someone gave the journal a value window, the
/// verifier owes a check that its init column is zero — and a check can be
/// forgotten where a missing column cannot (`docs/spec/public-values.md` §5).
#[test]
fn the_journals_family_has_no_init_column() {
    let vars = family::PUBLIC_WINDOW_HEIGHT.trailing_zeros();
    let journal = constraints::family_circuit(family::PUBLIC_OUTPUT, vars)
        .expect("the journal's family is registered");
    assert_eq!(
        journal.artifact.to_bytes(),
        zero_window_artifact(vars).to_bytes(),
        "the journal's circuit is no longer ZERO_WINDOWS'"
    );
    assert_eq!(
        journal.artifact.memory.len(),
        2,
        "the journal commits a teardown timestamp and a teardown value, and nothing else"
    );

    // Its two neighbours do have one, and it is `M[2]`.
    for (id, vars) in [
        (family::PUBLIC_INPUT, vars),
        (family::ADVICE_WINDOWS, HEIGHT.trailing_zeros()),
    ] {
        let circuit = constraints::family_circuit(id, vars).expect("registered");
        assert_eq!(
            circuit.artifact.to_bytes(),
            value_window_artifact(vars).to_bytes()
        );
        assert_eq!(circuit.artifact.memory.len(), 3);
        assert_eq!(circuit.artifact.memory[2], "init_value");
    }
}

/// None of the three families has an enforcing gate, a lookup or a channel,
/// and none has a setup column: each is two leaves and a product tree, degree
/// 1 throughout (`docs/spec/public-values.md` §4). A family that grew one
/// would owe a manifest entry and a soundness argument neither this stage nor
/// its spec page gives it.
#[test]
fn the_three_families_are_two_leaves_and_a_product_tree() {
    for (id, vars) in [
        (family::PUBLIC_INPUT, 8),
        (family::PUBLIC_OUTPUT, 8),
        (family::ADVICE_WINDOWS, HEIGHT.trailing_zeros()),
    ] {
        let c = constraints::family_circuit(id, vars).expect("registered");
        assert!(c.channels.is_empty(), "{id}: a channel");
        assert!(c.artifact.lookups.is_empty(), "{id}: a lookup");
        assert!(c.artifact.setup.is_empty(), "{id}: a setup column");
        assert!(c.artifact.witness.is_empty(), "{id}: a witness column");
        assert_eq!(
            c.artifact.outputs.len(),
            2,
            "{id}: the two roots, and no more"
        );
        assert!(!c.reads_generic_table(), "{id}: the generic table");
    }
}

// ---------------------------------------------------------------------------
// The statement rules
// ---------------------------------------------------------------------------

/// A `VmConfig` with every family the window rules need, at `h`.
fn config(h: u32) -> VmConfig {
    VmConfig {
        families: vec![
            (family::ADD_SUB_LUI_AUIPC, 1 << 20),
            (family::INIT_TEARDOWN, h),
            (family::ZERO_WINDOWS, h),
            (family::PUBLIC_INPUT, family::PUBLIC_WINDOW_HEIGHT),
            (family::PUBLIC_OUTPUT, family::PUBLIC_WINDOW_HEIGHT),
            (family::ADVICE_WINDOWS, h),
        ],
        bytecode_size_words: 1 << 20,
    }
}

/// `shard_counts` for [`config`]: add/sub, init, zero, input, output, advice.
fn counts(zero: u32, advice: u32) -> Vec<u32> {
    vec![1, 1, zero, 1, 1, advice]
}

/// The positive control, and the window rules holding on it.
#[test]
fn the_window_rules_take_an_honest_statement() {
    let h = 1 << 16;
    assert_eq!(
        check_memory_windows(&config(h), &counts(2, 3), &[1, 2]),
        Ok(())
    );
    assert_eq!(check_memory_windows(&config(h), &counts(0, 0), &[]), Ok(()));
}

/// Each of the three new rules refuses what it is for, by name
/// (`docs/spec/public-values.md` §2 and §4).
#[test]
fn the_window_rules_refuse_each_of_their_controls() {
    let h = 1 << 16;

    // The two public families prove exactly one shard each: a count a prover
    // could drop is a way to publish nothing while having published something.
    for (i, who) in [(3, "PUBLIC_INPUT"), (4, "PUBLIC_OUTPUT")] {
        for bad in [0, 2] {
            let mut c = counts(1, 0);
            c[i] = bad;
            let e = check_memory_windows(&config(h), &c, &[1]).unwrap_err();
            assert!(
                e.contains(who),
                "{who} at {bad} shards was refused with {e:?}"
            );
        }
    }

    // The advice windows have to fit below the top of the address space.
    let fits = (1u64 << 30) / h as u64 - advice_first_window(h) as u64;
    assert_eq!(
        check_memory_windows(&config(h), &counts(0, fits as u32), &[]),
        Ok(()),
        "exactly the region is admitted"
    );
    assert_eq!(
        check_memory_windows(&config(h), &counts(0, fits as u32 + 1), &[]),
        Err("the advice windows do not fit below the top of the address space")
    );

    // The advice windows start where the zero windows stop, so the two lists
    // are disjoint by arithmetic and not by a rule.
    assert_eq!(advice_first_window(h) as u64, (1u64 << 29) / h as u64);
}

/// A config missing any of the three families, or with a public family at the
/// wrong height, does not pass the window rules — so it does not decode
/// (`VmConfig::from_bytes` runs `window_height`), which is the check on bytes
/// a verifier was handed.
#[test]
fn a_config_without_the_new_families_is_refused() {
    let h = 1 << 16;
    for drop in [
        family::PUBLIC_INPUT,
        family::PUBLIC_OUTPUT,
        family::ADVICE_WINDOWS,
    ] {
        let mut c = config(h);
        let at = c.families.iter().position(|(f, _)| *f == drop).unwrap();
        c.families.remove(at);
        let mut n = counts(0, 0);
        n.remove(at);
        assert!(
            check_memory_windows(&c, &n, &[]).is_err(),
            "a config without {drop} was admitted"
        );
        assert!(
            VmConfig::from_bytes(&c.to_bytes()).is_none(),
            "a config without {drop} decoded"
        );
    }

    for wrong in [family::PUBLIC_INPUT, family::PUBLIC_OUTPUT] {
        let mut c = config(h);
        let at = c.families.iter().position(|(f, _)| *f == wrong).unwrap();
        c.families[at].1 = 1 << 16;
        assert_eq!(
            verifier_core::window_height(&c),
            Err("the public value families are at family::PUBLIC_WINDOW_HEIGHT")
        );
        assert!(VmConfig::from_bytes(&c.to_bytes()).is_none());
    }

    // And a window height too small to hold both public windows inside RAM
    // window 0, where `V[ram_live]` masks them.
    let mut c = config(1 << 8);
    c.families.retain(|(f, _)| *f != family::ADD_SUB_LUI_AUIPC);
    assert_eq!(
        verifier_core::window_height(&c),
        Err("the window height puts a public window outside RAM window 0")
    );
    assert!(
        4 * (1u64 << 16)
            >= guest_memory::PUBLIC_OUTPUT_ORIGIN as u64 + guest_memory::PUBLIC_WINDOW_BYTES as u64,
        "2^16 is the smallest window height that does hold them"
    );
}

/// The two public windows are where the constants say, and inside the hole the
/// RAM window families leave: `V[ram_live]` masks RAM window 0 below
/// `RAM_ORIGIN` at every height, so nothing else initializes them.
#[test]
fn the_public_windows_are_inside_the_hole() {
    let h = family::PUBLIC_WINDOW_HEIGHT;
    assert_eq!(
        guest_memory::PUBLIC_INPUT_ORIGIN,
        4 * h * family::PUBLIC_INPUT_WINDOW
    );
    assert_eq!(
        guest_memory::PUBLIC_OUTPUT_ORIGIN,
        4 * h * family::PUBLIC_OUTPUT_WINDOW
    );
    assert_eq!(
        guest_memory::PUBLIC_OUTPUT_ORIGIN,
        guest_memory::PUBLIC_INPUT_ORIGIN + guest_memory::PUBLIC_WINDOW_BYTES,
        "the two windows are adjacent and do not overlap"
    );
    let end = guest_memory::PUBLIC_OUTPUT_ORIGIN + guest_memory::PUBLIC_WINDOW_BYTES;
    assert!(end <= guest_memory::RAM_ORIGIN, "both are below RAM");
    // And neither claims address 0, so a null dereference still cannot
    // balance: `addressable` refuses it below.

    // What the executor will and will not let a guest reach.
    assert!(!trace::addressable(0));
    assert!(!trace::addressable(guest_memory::PUBLIC_INPUT_ORIGIN - 4));
    assert!(trace::addressable(guest_memory::PUBLIC_INPUT_ORIGIN));
    assert!(trace::addressable(end - 4));
    assert!(!trace::addressable(end));
    assert!(!trace::addressable(guest_memory::RAM_ORIGIN - 4));
    assert!(trace::addressable(guest_memory::RAM_ORIGIN));
    assert!(trace::addressable(guest_memory::ADVICE_ORIGIN));
    assert!(trace::addressable(0xffff_fffc));
    assert!(!trace::in_ram(guest_memory::ADVICE_ORIGIN));
}
