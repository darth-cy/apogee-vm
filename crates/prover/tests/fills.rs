//! Every delegation family's fill writes **exactly** its circuit's committed
//! columns: each address once, and the whole range.
//!
//! This is the cheap half of what a delegation shard's proof would show, and
//! it is here because the expensive half is `#[ignore]`d.
//!
//! **Two of these are themselves `#[ignore]`d since S26c, and for memory rather
//! than time.** `MOD_MUL` and `EC_ADD` are at `2^16` — `RANGE16`'s table
//! needs sixteen variables — so a fill of either is its full committed width over
//! 65,536 rows, and `EC_ADD`'s width is 1,420. **Measured at S26c**, when
//! `KECCAK_F` was one permutation a row at `2^8` — 3,764 committed columns over
//! 256 rows, so a couple of megabytes and no contribution to either figure: the
//! four remaining tests were 1.72 GiB and 1.73 s, and all six **19.1 GiB** in
//! 6.18 s. Neither figure has been re-measured since, and the keccak fill is
//! what moved under both — 0.52 GiB at S26d's `2^16` and **2.08 GiB** at the
//! `2^18` this file's `common::KECCAK_VARS` takes now, which is 2.08 GiB the
//! four did not carry before. Do not add that to the 19.1: a peak is a maximum,
//! the deferred run is `--test-threads=1`, and under `--ignored` the keccak fill
//! is not in it at all. The two that
//! cost that are a dev-server run (root `CLAUDE.md`'s deferred list). What still
//! holds those two circuits in ordinary CI is `crates/checker/tests/{mod_mul,ec_add}.rs`,
//! which evaluate the same gates row-locally at the same height from witnesses
//! derived independently of any fill — so the *circuits* stay covered and it is
//! the *fill* that does not, which is this file's own subject and worth being
//! plain about. `prove_shard` reads
//! the fill's columns back by address through `BaseLayer::get`, so a fill that
//! writes one address twice silently drops a column and leaves another unset,
//! and `gkr_part` panics on `"a witness column"` at the far end of a 113-second
//! proof with nothing said about which one.
//!
//! The way that happens is a shared builder and a family that lays its columns
//! out differently. Two builders serve the six delegation families —
//! `prover::fill::delegation_frame` for the three that decompose into bits and
//! `delegation_frame_range16` for the three that range-check through `RANGE16` —
//! and both write the frame's own witness columns at `W[0]`. S21's `keccak` was
//! the one exception, putting its 1,600 state bits first and its frame's bits at
//! `W[1600]`, which is why the bit builder carried a `witness_base` offset until
//! S26d re-shaped that family. What replaces the offset is the invariant below:
//! **every** delegation frame's witness columns start at `W[0]`. Nothing about
//! the addresses depends on what the guest computed, so one invocation of each is
//! as decisive as a full shard.

use constants::family;
use constraints::PolyAddress;
use constraints::{
    ec_add as ea_circuit, fr_arith as fa_circuit, keccak as kec_circuit, mod_mul as mm_circuit,
    poseidon2 as p2_circuit,
};
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
///
/// **`w` excludes the channel multiplicities**, which are the last columns of
/// the witness subtree and are **not the fill's**: `prover`'s shard-column
/// assembly appends them with `trace::build_multiplicities`, after the fill and
/// over the tuples the fill wrote. A caller passes
/// `WITNESS_COLUMNS - channels().len()` for a family that carries a channel,
/// which since S26c is `MOD_MUL` and `EC_ADD` and since S26d `KECCAK_F` too —
/// and that family carries **two**, so the subtraction is not always one.
fn covers(program: &Program, archive: &trace::TraceArchive, family: u32, m: usize, w: usize) {
    let name = program::family_name(family);
    let height = program
        .config
        .families
        .iter()
        .find(|(f, _)| *f == family)
        .map(|(_, h)| *h as usize)
        .unwrap_or_else(|| panic!("{name} is in the config"));
    let src = ShardSource::archived(program, archive, family, 0, height as u32, 0)
        .expect("the shard's rows");
    let fill = family_fill(family).unwrap_or_else(|| panic!("{name} has a fill"));
    let out = fill(&src).unwrap_or_else(|e| panic!("{name} fills: {e}"));
    let (memory, witness, duplicates) = addresses(&out);
    assert_eq!(duplicates, 0, "{name} writes an address twice");
    assert_eq!(memory, (0..m as u32).collect::<Vec<_>>(), "{name}'s M");
    assert_eq!(witness, (0..w as u32).collect::<Vec<_>>(), "{name}'s W");
}

/// S21's family, re-shaped at S26d: one round a row, 1,556 witness columns and
/// not a bit among them. The regression this guards is the same as the other
/// five's — a column the circuit declares and the fill never writes is a
/// `gkr_part` panic at the far end of a proof — and this family has the most
/// blocks to get wrong: nine byte-wide stages, a 24-column one-hot selector and
/// a four-column round constant, one of which (`rho_mask`) is 22 lanes and not
/// 25.
///
/// **It subtracts `channels().len()` since S26d**, like `MOD_MUL`'s and
/// `EC_ADD`'s below: this family carried no channel until then, so the
/// unsubtracted constant was right and is not any more.
#[test]
fn the_keccak_fill_covers_its_circuit_exactly() {
    let program = common::keccak_program();
    let archive = common::keccak_archive(&program);
    covers(
        &program,
        &archive,
        family::KECCAK_F,
        kec_circuit::MEMORY_COLUMNS,
        kec_circuit::WITNESS_COLUMNS - kec_circuit::channels().len(),
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

/// S26's, whose frame also starts at `W[0]` and whose quotient, borrow chain and
/// carries sit above four values' bits.
///
/// It is the one delegation fill that computes a column the execution never
/// recorded — the quotient — so "covers its circuit exactly" is also the check
/// that `mod_mul_witness` wrote every carry it was supposed to.
#[test]
#[ignore = "DEFERRED: fills two 2^16 delegation shards -- EC_ADD alone is 1,420 committed columns over 65,536 rows. With `every_delegation_fill_satisfies_every_gate` the file peaked at 19.1 GiB when that was measured at S26c, above what a GitHub runner has"]
fn the_mod_mul_and_ec_add_fills_cover_their_circuits_exactly() {
    let program = common::mod_mul_program();
    let archive = common::mod_mul_archive(&program);
    // Less the one multiplicity column each: `trace::build_multiplicities`
    // appends those after the fill, over the tuples the fill wrote.
    covers(
        &program,
        &archive,
        family::MOD_MUL,
        mm_circuit::MEMORY_COLUMNS,
        mm_circuit::WITNESS_COLUMNS - constraints::mod_mul::channels().len(),
    );
    covers(
        &program,
        &archive,
        family::EC_ADD,
        constraints::ec_add::MEMORY_COLUMNS,
        constraints::ec_add::WITNESS_COLUMNS - constraints::ec_add::channels().len(),
    );
}

/// **Every gate holds on the fill's own columns**, for each of the three
/// delegation families whose fill S26 and S26c wrote.
///
/// `covers` above is set equality over addresses, and a permutation is
/// invisible to it: swap two values in the fill's list and every column is
/// still written exactly once, at an address the circuit has, with a value
/// that belongs to another column. That failure surfaces as
/// `LayerInconsistency { layer }` from a deferred proof, naming nothing.
///
/// This is the fast test that catches it, and the mutations it is here for are
/// specific: a value index renumbered against the circuit's own `VALUES`, a
/// `< m` chain computed against the wrong modulus — `fill::borrow_chain`
/// subtracts `constants::FR_MODULUS` and would be right for one of the four
/// selectors — a selector column set from the wrong code, and a padding row's
/// chain computed against the shard's modulus rather than against its own zero
/// one. None of those is visible to `covers`, to `checker`'s hand-built
/// witness, or to anything else in ordinary CI.
///
/// **`EC_ADD` is here because its fill was wrong and this is what says so.**
/// S26c wrote it against a `below_modulus` gate that read `b_7 = enable`, so a
/// non-reading value's chain was filled with zeros; the gate is
/// `enable·(1 - b_7) = 0` and the chain's sixteen `canonical` gates are
/// ungated, so the zeros satisfy them only where `v = m`. Nothing in the
/// executor, the guests or the shape tests could see it.
#[test]
#[ignore = "DEFERRED: same two 2^16 fills; the sampled row evaluation is cheap and the fills are not. See the sibling test's note"]
fn every_delegation_fill_satisfies_every_gate() {
    let program = common::mod_mul_program();
    let archive = common::mod_mul_archive(&program);
    // The first 32 rows cover every selector the fixture uses — `mod-mul-ops`
    // calls the ABI three times per code before it reaches a library seam — and
    // the last 4 are padding, which at `2^16` every shard has.
    for family in [family::MOD_MUL, family::EC_ADD] {
        sampled_rows_hold(
            &program,
            &archive,
            family,
            common::DELEGATION_CHANNEL_VARS,
            32,
            4,
        );
    }
}

/// `SHA256_COMP`'s fill: every address of its `2^18` circuit exactly once.
///
/// S26c's whole-compression row was at `2^8`, where a forward pass over the
/// filled shard was 137 MB and this test ran one. S26e's four-round row is at
/// `2^18`, where a pass is the ~23 GB a deferred suite pays, so this is the
/// address check the other channel-carrying families get, and the values are
/// `crates/checker/tests/sha256.rs`' — which evaluates the fill's own columns,
/// multiplicities included, against every gate and every obligation, row by
/// row, over this same guest's trace.
#[test]
fn the_sha256_fill_covers_its_circuit_exactly() {
    let program = common::sha256_program();
    let archive = common::sha256_archive(&program);
    covers(
        &program,
        &archive,
        family::SHA256_COMP,
        constraints::sha256::MEMORY_COLUMNS,
        constraints::sha256::WITNESS_COLUMNS - constraints::sha256::channels().len(),
    );
}

/// Evaluate a sample of a filled shard's rows against the gates, row-locally.
///
/// **Why a sample and not a forward pass.** `MOD_MUL` and `EC_ADD` carry the
/// `RANGE16` channel and both take that channel's `2^16` floor as their height
/// (`docs/spec/delegation.md` §10.3), and `gkr::forward` over one is 4.6 GB and
/// 18.3 GB respectively — deferred-suite figures, in a suite whose whole point
/// is to be fast. A relation is **row-local**, so evaluating rows is the same
/// statement per row at a few megabytes.
///
/// The rows chosen are the first `head` and the last `tail`, which is where the
/// mutations this test exists for live: a renumbered value index, a chain
/// against the wrong modulus and a selector from the wrong code all show on the
/// first live rows, and a padding row's chain computed against the shard's
/// modulus rather than its own zero one shows only at the end.
fn sampled_rows_hold(
    program: &Program,
    archive: &trace::TraceArchive,
    family: u32,
    vars: u32,
    head: usize,
    tail: usize,
) {
    let name = program::family_name(family);
    let circuit = constraints::family_circuit(family, vars)
        .unwrap_or_else(|| panic!("{name} is registered at {vars} variables"));
    let a = &circuit.artifact;
    let mut challenges = gkr::ExternalChallenges::new();
    for (slot, value) in [
        (constants::challenge_slot::MEM_GAMMA, 3u64),
        (constants::challenge_slot::MEM_ALPHA_ADDR, 5),
        (constants::challenge_slot::MEM_ALPHA_TS, 7),
        (constants::challenge_slot::MEM_ALPHA_VAL, 11),
    ] {
        challenges.insert(slot, field::Fr::from_u64(value));
    }
    gkr::insert_lookup_challenges(
        &mut challenges,
        field::Fr::from_u64(13),
        field::Fr::from_u64(17),
        a,
    );

    let height = 1u32 << vars;
    let fill = family_fill(family).unwrap_or_else(|| panic!("{name} has a fill"));
    let invocations = archive
        .family_traces()
        .delegation(family)
        .unwrap_or_else(|| panic!("{name} has a buffer"))
        .len();
    assert!(invocations > 0, "{name}: the fixture invokes it not at all");
    let shards = invocations.div_ceil(height as usize);
    for shard in 0..shards as u32 {
        let src = ShardSource::archived(program, archive, family, shard, height, 0)
            .expect("the shard's rows");
        let columns = fill(&src).expect("the shard fills");
        // The multiplicities are not the fill's (see `covers`), and no gate
        // reads them, so zero is what a row-local evaluation needs.
        let mut columns = columns;
        for address in a.committed() {
            if !columns.iter().any(|(at, _)| *at == address) {
                columns.push((
                    address,
                    poly::MultilinearPoly::new(poly::PolyBacking::Fr(vec![
                        field::Fr::ZERO;
                        height as usize
                    ])),
                ));
            }
        }
        let rows = (0..head.min(height as usize))
            .chain((height as usize).saturating_sub(tail)..height as usize);
        for row in rows {
            let committed: Vec<field::Fr> = a
                .committed()
                .into_iter()
                .map(|address| {
                    columns
                        .iter()
                        .find(|(at, _)| *at == address)
                        .unwrap_or_else(|| panic!("{name}: no column for {address}"))
                        .1
                        .get(row)
                })
                .collect();
            let virtuals: Vec<field::Fr> = a
                .virtuals
                .iter()
                .map(|(k, _)| gkr::virtual_at_row(*k, row))
                .collect();
            let mut scratch = vec![field::Fr::ZERO; a.scratch.len()];
            let mut lower = committed.clone();
            for k in 0..a.depth() {
                if a.layers[k].halving {
                    break;
                }
                let v: &[field::Fr] = if k == 0 { &virtuals } else { &[] };
                let values = gkr::gate_values(a, k, &lower, &[], v, &challenges);
                let produced = values[..a.layers[k].producing.len()].to_vec();
                for (j, value) in produced.iter().enumerate() {
                    let address = PolyAddress::Inner {
                        layer: k as u32 + 1,
                        offset: j as u32,
                    };
                    let slot = a
                        .scratch
                        .iter()
                        .position(|sc| sc.address == address)
                        .expect("every inner column has a scratch slot");
                    scratch[slot] = *value;
                }
                lower = produced;
            }
            let w = checker::WitnessRow {
                committed,
                row,
                scratch,
            };
            let violated = checker::violated_relations(a, &w, &challenges);
            assert!(
                violated.is_empty(),
                "{name} shard {shard} row {row} breaks {violated:?}"
            );
        }
    }
}

/// **Every** delegation frame's witness columns start at `W[0]`, which is what
/// lets one builder per range convention serve every family without an offset.
///
/// This is the S26d replacement for `the_frame_witness_base_is_per_family`: that
/// test pinned `keccak`'s frame bits sitting at `W[1600]`, the one exception, and
/// the offset parameter that existed for it alone is deleted. The mutation this
/// catches is the one that matters now — a later delegation family putting its
/// own columns before the frame's, which the shared builder would silently
/// overwrite.
///
/// The three bit-decomposing families' frames start with a gap **bit**; the three
/// that range-check through `RANGE16` start with a gap **chunk**.
#[test]
fn every_frame_witness_block_starts_at_zero() {
    for a in [p2_circuit::gap_bit(0, 0), fa_circuit::gap_bit(0, 0)] {
        assert_eq!(a, PolyAddress::Witness(0), "S23's frames start at W[0]");
    }
    for a in [
        mm_circuit::gap_chunk(0, 0),
        ea_circuit::gap_chunk(0, 0),
        kec_circuit::gap_chunk(0, 0),
    ] {
        assert_eq!(
            a,
            PolyAddress::Witness(0),
            "a RANGE16 frame's chunks start at W[0]"
        );
    }
}
