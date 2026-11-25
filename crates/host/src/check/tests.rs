//! `host::check` over the guests the executor's suites run, a guest that never
//! exits, and tamper twins written into the witness through the harness's own
//! cell writer, `checker::tamper_columns`.
//!
//! Nothing here proves. A guest's execution families are at `2^20`, the
//! least menu height a family with a timestamp channel has, and every other
//! family at `2^16`, as the proving suites' are; two shards are in flight.

#[path = "../../../emulator/tests/common/mod.rs"]
mod common;

use checker::{tamper_columns, Cell};
use constants::family::{self, ADD_SUB_LUI_AUIPC as ADD, INIT_TEARDOWN as INIT};
use constants::{guest_memory, lookup_channel};
use loader::{ProgramImage, Segment, Slot};
use program::{decode_program, ProgramParams};
use prover::{Program, ProverSetup};

use super::*;

const IN_FLIGHT: usize = 2;

/// The execution families at `2^20`, every other family at `2^16`.
fn params() -> ProgramParams {
    let mut heights = [1 << 16; family::COUNT as usize];
    for f in family::ADD_SUB_LUI_AUIPC..=family::ATOMICS {
        heights[f as usize] = 1 << 20;
    }
    ProgramParams {
        heights,
        ..ProgramParams::defaults()
    }
}

fn setup_of(image: ProgramImage) -> ProverSetup {
    let (tables, config) = decode_program(&image, &params()).expect("the guest decodes");
    ProverSetup::new(Program {
        image,
        tables,
        config,
    })
    .expect("the guest registers")
}

fn io_of(name: &str) -> GuestIo {
    common::with_advice(&common::input_of(name), &common::advice_of(name))
}

/// Every guest `crates/emulator/tests/streaming.rs` streams passes but
/// `opcodes`: each shard's every row, channel and public window, the windows
/// and the memory multiset, and the journal is the executor's. `opcodes`
/// calls an unassigned ecall, which the executor answers and no family
/// proves (`docs/spec/ecall-abi.md` §4), so the prover's fill refuses it, as
/// it would refuse to prove it.
#[test]
fn every_streamed_guest_passes_the_check() {
    for name in [
        "fib",
        "heap",
        "atomics",
        "rvc-dense",
        "addsub",
        "control",
        "alu",
        "mem",
        "shards",
        "precompiles",
    ] {
        let setup = setup_of(common::image(name));
        let io = io_of(name);
        let executed = emulator::run(&setup.program.image, &io).expect("the guest runs");
        let report = check(&setup, &io, IN_FLIGHT, u64::MAX)
            .unwrap_or_else(|e| panic!("{name}: the check refuses: {e}"));
        assert_eq!(report.cycles, executed.cycle_count, "{name}");
        assert_eq!(report.journal, executed.io.output, "{name}");
        assert!(report.peak_in_flight <= IN_FLIGHT, "{name}");
    }
    let setup = setup_of(common::image("opcodes"));
    let refused = check(&setup, &io_of("opcodes"), IN_FLIGHT, u64::MAX);
    assert!(
        matches!(&refused, Err(CheckFailure::Prover(ProverError::Trace(e))) if e.contains("ecall")),
        "{refused:?}"
    );
}

/// A guest that never exits, `addi a0, a0, 1; j -4`, is stopped by the cap
/// with the executor's own error, before any column is built; and a guest
/// that does exit is stopped the same way under a cap below its cycles.
#[test]
fn a_guest_that_never_exits_stops_at_the_cap() {
    let words: [u32; 2] = [0x0015_0513, 0xffdf_f06f];
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let image = ProgramImage {
        entry: guest_memory::RAM_ORIGIN,
        segments: vec![Segment {
            vaddr: guest_memory::RAM_ORIGIN,
            mem_len: 8,
            bytes,
        }],
        slot_base: guest_memory::RAM_ORIGIN,
        slots: words
            .iter()
            .flat_map(|&word| {
                [
                    Slot::Instruction {
                        word,
                        compressed: false,
                    },
                    Slot::MidInstruction,
                ]
            })
            .collect(),
        delegations: Vec::new(),
    };
    let setup = setup_of(image);
    let io = common::with_advice(&[], &[]);
    assert_eq!(
        check(&setup, &io, IN_FLIGHT, 10_000),
        Err(CheckFailure::Execution(EmuError::CycleLimit {
            limit: 10_000
        }))
    );

    let setup = setup_of(common::image("shards"));
    assert_eq!(
        check(&setup, &io_of("shards"), IN_FLIGHT, 100_000),
        Err(CheckFailure::Execution(EmuError::CycleLimit {
            limit: 100_000
        }))
    );
}

/// The committed column `name` of `family`'s circuit.
fn col(family: u32, name: &str) -> PolyAddress {
    constraints::family_circuit(family, 20)
        .expect("the family's circuit at 2^20")
        .artifact
        .column(name)
        .unwrap_or_else(|| panic!("family {family} has no column `{name}`"))
}

/// `addsub` checked with `cells` written into its witness, each shard's
/// channels recounted as the honest prover would recount them.
fn tampered(setup: &ProverSetup, cells: &[Cell]) -> Result<CheckReport, CheckFailure> {
    let edit = |shard: &mut ShardWitness| {
        tamper_columns(
            setup,
            (shard.family, shard.index),
            &mut shard.columns,
            cells,
        )
    };
    check_edited(setup, &io_of("addsub"), IN_FLIGHT, u64::MAX, &edit)
}

/// The cell at `row` of the honest `addsub` witness's `(family, 0)` shard.
fn honest(setup: &ProverSetup, family: u32, address: PolyAddress, row: usize) -> Fp {
    let seen = std::sync::Mutex::new(None);
    let edit = |shard: &mut ShardWitness| {
        if (shard.family, shard.index) == (family, 0) {
            let (_, column) = shard
                .columns
                .iter()
                .find(|(a, _)| *a == address)
                .expect("the shard has the column");
            *seen.lock().unwrap() = Some(column.get_base(row));
        }
    };
    check_edited(setup, &io_of("addsub"), IN_FLIGHT, u64::MAX, &edit).expect("addsub checks");
    seen.into_inner().unwrap().expect("the shard was checked")
}

fn cell(family: u32, address: PolyAddress, row: usize, value: Fp) -> Cell {
    Cell {
        family,
        shard: 0,
        address,
        row,
        value,
    }
}

/// The tamper suite's first three twins, `checker/tests/tamper.rs`' a2–a4, on
/// `addsub`'s witness: a semantics cell breaks its relation at its row; a
/// teardown value no gate reads breaks the memory multiset alone; a
/// multiplicity breaks its channel, with no tuple outside a table.
///
/// `addsub`'s row 4 is `add t2, t0, t1`, carrying out of both words; row
/// `2^14` of `INIT_TEARDOWN` is the word at `RAM_ORIGIN`, its first
/// instruction, which no row reads or writes.
#[test]
fn a_tampered_witness_is_refused_by_name() {
    let setup = setup_of(common::image("addsub"));

    let c0 = col(ADD, "c0");
    assert_eq!(
        honest(&setup, ADD, c0, 4),
        Fp::ONE,
        "the carrying add carries"
    );
    assert_eq!(
        tampered(&setup, &[cell(ADD, c0, 4, Fp::ZERO)]),
        Err(CheckFailure::Relation {
            family: ADD,
            shard: 0,
            row: 4,
            relation: "add_lo".to_string(),
        })
    );

    let row = 1 << 14;
    let word = honest(&setup, INIT, PolyAddress::Memory(1), row);
    assert!(matches!(
        tampered(
            &setup,
            &[cell(INIT, PolyAddress::Memory(1), row, word + Fp::ONE)]
        ),
        Err(CheckFailure::Memory(_))
    ));

    let mult = col(ADD, "mult_range16");
    let m = honest(&setup, ADD, mult, 0);
    assert_eq!(
        tampered(&setup, &[cell(ADD, mult, 0, m + Fp::ONE)]),
        Err(CheckFailure::Channel {
            family: ADD,
            shard: 0,
            channel: lookup_channel::RANGE16,
            unmatched: None,
        })
    );
}
