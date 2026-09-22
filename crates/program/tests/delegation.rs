//! Static detachment for delegation families: `docs/spec/delegation.md` §7.
//!
//! A delegation family claims no pc, so the instruction sweep can never learn
//! that a program calls one — the ecall number lives in `a7` at run time.
//! What decides membership is a declaration record the shim emits, and the
//! whole mechanism is **reachability**: the record is referenced by the shim
//! and by nothing else, so the linker keeps it exactly when the shim is
//! linked.
//!
//! That is a property of a build, not of a source file, so this suite holds
//! every committed guest to it — the ones that declare and, more importantly,
//! the ones that must not. A `#[used]` record, or a shim whose number the
//! optimiser folds into an immediate, each break exactly one half of it and
//! each is caught here.

mod common;

use constants::{delegation, ecall, family};
use loader::{ProgramImage, Segment};
use program::{
    declared_delegations, decode_program, delegation_ecall, delegation_family,
    delegation_frame_words, ProgramError, DELEGATIONS,
};

/// A record for `number`, as the guest SDK builds one.
fn record(number: u32) -> Vec<u8> {
    let mut out = delegation::MARKER_MAGIC.to_vec();
    out.extend_from_slice(&number.to_le_bytes());
    out
}

/// An image whose one file-backed segment holds `bytes` at `RAM_ORIGIN`.
fn image_of(bytes: Vec<u8>) -> ProgramImage {
    ProgramImage {
        entry: constants::guest_memory::RAM_ORIGIN,
        segments: vec![Segment {
            vaddr: constants::guest_memory::RAM_ORIGIN,
            mem_len: bytes.len() as u32,
            bytes,
        }],
        slot_base: constants::guest_memory::RAM_ORIGIN,
        slots: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// The one table, read three ways, and its two rules: every number is in the
/// precompile range, and every family is above the two window families so a
/// `VmConfig` lists it last.
#[test]
fn the_registry_is_one_table() {
    assert_eq!(
        DELEGATIONS.len(),
        2,
        "S21 registers KECCAK_F and S22 ECRECOVER"
    );
    // Append-only, and ascending by family id: the two rules the table's own
    // doc comment states (`docs/spec/delegation.md` §3).
    assert!(
        DELEGATIONS.windows(2).all(|w| w[0].0 < w[1].0),
        "the registry is ascending by family id"
    );
    let numbers: std::collections::BTreeSet<u32> = DELEGATIONS.iter().map(|(_, n, _)| *n).collect();
    assert_eq!(
        numbers.len(),
        DELEGATIONS.len(),
        "no two delegation families answer one ecall number"
    );
    for (fam, number, words) in DELEGATIONS {
        assert_eq!(delegation_family(number), Some(fam));
        assert_eq!(delegation_ecall(fam), Some(number));
        assert_eq!(delegation_frame_words(fam), Some(words));
        assert!(
            (ecall::PRECOMPILE_FIRST..=ecall::PRECOMPILE_LAST).contains(&number),
            "a delegation is a precompile: {number:#x}"
        );
        assert!(
            fam > family::ZERO_WINDOWS,
            "a delegation family's id is above the window families', so a config lists it last"
        );
        assert!(
            !program::claims_pcs(fam),
            "a delegation family owns no cycle and claims no pc"
        );
        assert!(
            program::lookup_tuple(fam).is_empty(),
            "a delegation family is invoked, never decoded, so it has no table"
        );
    }
    assert_eq!(
        (
            delegation_family(ecall::EXIT),
            delegation_family(ecall::PRECOMPILE_POSEIDON2)
        ),
        (None, None),
        "neither exit nor the poseidon2 number is a delegation yet"
    );
    assert_eq!(delegation_frame_words(family::ADD_SUB_LUI_AUIPC), None);
    assert_eq!(
        (family::KECCAK_F, ecall::PRECOMPILE_KECCAK_F, 50),
        DELEGATIONS[0],
        "the keccak family, its number and its 50-word frame"
    );
}

// ---------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------

#[test]
fn a_record_declares_its_family() {
    let mut bytes = vec![0u8; 3];
    bytes.extend(record(ecall::PRECOMPILE_KECCAK_F));
    assert_eq!(
        declared_delegations(&image_of(bytes)),
        Ok(vec![family::KECCAK_F])
    );
}

#[test]
fn the_scan_is_byte_wise() {
    // A `static`'s address is the linker's. The record here sits at offset 1,
    // 2 and 3 of its segment in turn, and a word-wise scan would find none of
    // them — which would be a declaration silently lost.
    for pad in 0..8usize {
        let mut bytes = vec![0xffu8; pad];
        bytes.extend(record(ecall::PRECOMPILE_KECCAK_F));
        assert_eq!(
            declared_delegations(&image_of(bytes)),
            Ok(vec![family::KECCAK_F]),
            "a record at offset {pad}"
        );
    }
}

#[test]
fn a_family_declared_twice_is_one_declaration() {
    let mut bytes = record(ecall::PRECOMPILE_KECCAK_F);
    bytes.extend([0u8; 5]);
    bytes.extend(record(ecall::PRECOMPILE_KECCAK_F));
    assert_eq!(
        declared_delegations(&image_of(bytes)),
        Ok(vec![family::KECCAK_F])
    );
}

#[test]
fn a_number_no_family_answers_is_refused() {
    // Loud, because it means the guest and this preprocessor disagree about
    // the ABI — not silently ignored, which would make the guest's own call
    // fail much later and much less clearly.
    let base = constants::guest_memory::RAM_ORIGIN;
    for number in [0u32, ecall::EXIT, ecall::PRECOMPILE_POSEIDON2, 0x05ff] {
        assert_eq!(
            declared_delegations(&image_of(record(number))),
            Err(ProgramError::UnknownDelegation { addr: base, number }),
            "ecall {number:#x}"
        );
    }
}

#[test]
fn a_truncated_record_declares_nothing() {
    let full = record(ecall::PRECOMPILE_KECCAK_F);
    for len in 0..full.len() {
        assert_eq!(
            declared_delegations(&image_of(full[..len].to_vec())),
            Ok(Vec::new()),
            "{len} bytes of a record"
        );
    }
    assert_eq!(
        declared_delegations(&image_of(full)),
        Ok(vec![family::KECCAK_F])
    );
}

#[test]
fn a_segment_with_no_file_bytes_carries_no_record() {
    // `.bss` and the heap-and-stack reservation hold no image byte, wherever
    // they lie, and identity does not bind them either.
    let mut image = image_of(Vec::new());
    image.segments[0].mem_len = 1 << 20;
    assert_eq!(declared_delegations(&image), Ok(Vec::new()));
}

// ---------------------------------------------------------------------------
// Every committed guest
// ---------------------------------------------------------------------------

/// Acceptance 8's first half, over every guest in the tree: the two that call
/// or reference `guest_sdk::keccak256` declare `KECCAK_F`, and **no other
/// guest declares anything at all** — not even the ten that link the SDK.
///
/// The second clause is the one that matters. `guests/Cargo.toml` pins
/// `codegen-units = 1`, so the SDK is one object file; a `#[used]` record
/// would be in every guest that links it, `fib` included, and detachment
/// would mean nothing.
#[test]
fn every_guest_declares_exactly_what_it_links() {
    for name in common::GUESTS {
        let image = common::guest(name);
        let want: Vec<u32> = common::DECLARING_GUESTS
            .iter()
            .filter(|(g, _)| *g == name)
            .map(|(_, f)| *f)
            .collect();
        assert_eq!(
            declared_delegations(&image),
            Ok(want.clone()),
            "{name} declares the wrong set"
        );
        let config = decode_program(&image, &common::fitting(&image))
            .expect("the guest decodes")
            .1;
        let families: Vec<u32> = config.families.iter().map(|(f, _)| *f).collect();
        for (fam, _, _) in DELEGATIONS {
            assert_eq!(
                families.contains(&fam),
                want.contains(&fam),
                "{name}: the config's delegation families are the declared ones"
            );
        }
    }
    // The two halves are both non-empty, so neither clause is vacuous.
    // Four guests declare, six declarations between them, and most guests
    // declare nothing at all — which is the clause that matters: `#[used]`, or
    // one shared `link_section`, would put a record in every guest that links
    // the SDK.
    assert_eq!(common::DECLARING_GUESTS.len(), 6);
    let declaring: std::collections::BTreeSet<&str> =
        common::DECLARING_GUESTS.iter().map(|(g, _)| *g).collect();
    assert_eq!(declaring.len(), 4);
    assert!(common::GUESTS.len() > declaring.len() + 10);
}

/// Reachability survives `opt-level = 3`, which is the half of acceptance 8
/// the committed fixtures cannot show: they are built at `debug`.
///
/// This is the regression the `core::hint::black_box` in
/// `guest_sdk::delegation_number` exists for. Without it LLVM folds the
/// record's number into an immediate, the record becomes unreferenced, and
/// `keccak-test` declares **nothing** at `--release` while declaring
/// `KECCAK_F` at `--debug` — a guest whose provable family set depends on its
/// optimisation level. `fib` is the control in the other direction: it links
/// the same SDK object file and must declare nothing at either level, which is
/// what `#[used]` would break.
///
/// `#[ignore]`d because it builds two guests from source into fresh target
/// directories; run it with `--ignored`.
#[test]
#[ignore = "builds two guests from source at both optimisation levels"]
fn reachability_survives_the_optimiser() {
    for profile in ["debug", "release"] {
        for (name, want) in [("keccak-test", vec![family::KECCAK_F]), ("fib", Vec::new())] {
            let bytes = common::build_profile(name, &format!("deleg-{profile}"), profile);
            let image = loader::load_elf(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(
                declared_delegations(&image),
                Ok(want.clone()),
                "{name} at {profile} declares the wrong set"
            );
        }
    }
}

/// A declared family is in the `VmConfig` **last**, after the two window
/// families, and carries a table with no columns — it is invoked, never
/// decoded.
#[test]
fn a_declared_family_is_last_and_has_no_table() {
    let image = common::guest("keccak-test");
    let (tables, config) = decode_program(&image, &common::fitting(&image)).expect("it decodes");
    assert_eq!(
        config.families.last().map(|(f, _)| *f),
        Some(family::KECCAK_F)
    );
    let table = tables
        .family(family::KECCAK_F)
        .expect("a config family has a table");
    assert!(table.columns.is_empty(), "no columns");
    assert!(
        (0..table.height as usize).all(|row| !table.is_live(row)),
        "and no live row: the family claims no pc"
    );
    assert_eq!(program::field_mask(family::KECCAK_F), 0);
}
