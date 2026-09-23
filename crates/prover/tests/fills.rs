//! Every delegation family's fill writes **exactly** its circuit's committed
//! columns: each address once, and the whole range.
//!
//! This is the cheap half of what a delegation shard's proof would show, and
//! it is here because the expensive half is `#[ignore]`d. `prove_shard` reads
//! the fill's columns back by address through `BaseLayer::get`, so a fill that
//! writes one address twice silently drops a column and leaves another unset,
//! and `gkr_part` panics on `"a witness column"` at the far end of a 113-second
//! proof with nothing said about which one.
//!
//! The way that happens is a shared builder and a family that lays its columns
//! out differently. `prover::fill::delegation_frame` serves all three families,
//! but `constraints::keccak` — frozen at S21, before the shared module existed
//! — puts the input state's 1,600 bits at `W[0]` and the frame's gap and base
//! bits above them, while S23's two circuits put the frame's bits first. The
//! builder takes that offset as `witness_base`; pass 0 for keccak and its gap
//! bits land on top of the state's, which is exactly the shape this file
//! refuses. Nothing about the addresses depends on what the guest computed, so
//! one invocation of each is as decisive as a full shard.

use constants::family;
use constraints::PolyAddress;
use constraints::{fr_arith as fa_circuit, keccak as kec_circuit, poseidon2 as p2_circuit};
use prover::{family_fill, Program, ShardSource};

mod common;

/// The fill's addresses, split by kind, each sorted and de-duplicated with the
/// duplicate count kept.
fn addresses(out: &[(PolyAddress, poly::MultilinearPoly)]) -> (Vec<u32>, Vec<u32>, usize) {
    let (mut memory, mut witness) = (Vec::new(), Vec::new());
    for (a, _) in out {
        match a {
            PolyAddress::Memory(i) => memory.push(*i),
            PolyAddress::Witness(i) => witness.push(*i),
            other => panic!("a delegation fill writes only M and W, not {other:?}"),
        }
    }
    let total = memory.len() + witness.len();
    memory.sort_unstable();
    witness.sort_unstable();
    memory.dedup();
    witness.dedup();
    let duplicates = total - memory.len() - witness.len();
    (memory, witness, duplicates)
}

/// `family`'s fill over `archive`, held to `m` memory and `w` witness columns:
/// every address in `0..m` and `0..w` exactly once, and nothing else.
fn covers(program: &Program, archive: &trace::TraceArchive, family: u32, m: usize, w: usize) {
    let name = program::family_name(family);
    let height = program
        .config
        .families
        .iter()
        .find(|(f, _)| *f == family)
        .map(|(_, h)| *h as usize)
        .unwrap_or_else(|| panic!("{name} is in the config"));
    let src = ShardSource {
        program,
        archive,
        family,
        index: 0,
        height,
        window: 0,
    };
    let fill = family_fill(family).unwrap_or_else(|| panic!("{name} has a fill"));
    let out = fill(&src).unwrap_or_else(|e| panic!("{name} fills: {e}"));
    let (memory, witness, duplicates) = addresses(&out);
    assert_eq!(duplicates, 0, "{name} writes an address twice");
    assert_eq!(memory, (0..m as u32).collect::<Vec<_>>(), "{name}'s M");
    assert_eq!(witness, (0..w as u32).collect::<Vec<_>>(), "{name}'s W");
}

/// S21's family, whose frame's witness columns start at `W[1600]`. This is the
/// regression: with the shared builder's default base its 1,900 gap bits and
/// 60 base bits land on the state's 1,600, `W[1600..3560]` is never written,
/// and the shard does not prove.
#[test]
fn the_keccak_fill_covers_its_circuit_exactly() {
    let program = common::keccak_program();
    let archive = common::keccak_archive(&program);
    covers(
        &program,
        &archive,
        family::KECCAK_F,
        kec_circuit::MEMORY_COLUMNS,
        kec_circuit::WITNESS_COLUMNS,
    );
}

/// S23's two, whose frames start at `W[0]` and whose own columns sit above.
#[test]
fn the_recursion_fills_cover_their_circuits_exactly() {
    let program = common::recursion_program();
    let archive = common::recursion_archive(&program);
    covers(
        &program,
        &archive,
        family::POSEIDON2,
        p2_circuit::MEMORY_COLUMNS,
        p2_circuit::WITNESS_COLUMNS,
    );
    covers(
        &program,
        &archive,
        family::FR_ARITH,
        fa_circuit::MEMORY_COLUMNS,
        fa_circuit::WITNESS_COLUMNS,
    );
}

/// The three circuits do **not** agree on where a frame's witness columns
/// start, which is the whole reason the builder takes a base. Stated here so
/// that a later family copying one of them sees the choice rather than
/// inheriting it.
#[test]
fn the_frame_witness_base_is_per_family() {
    assert_eq!(
        kec_circuit::gap_bit(0, 0),
        PolyAddress::Witness(constants::keccak::STATE_BITS as u32),
        "keccak's frame bits sit above the state's"
    );
    for a in [p2_circuit::gap_bit(0, 0), fa_circuit::gap_bit(0, 0)] {
        assert_eq!(a, PolyAddress::Witness(0), "S23's frames start at W[0]");
    }
}
