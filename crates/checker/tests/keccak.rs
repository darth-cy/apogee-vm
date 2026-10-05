//! The keccak-f[1600] round circuit, gate by gate and obligation by obligation.
//!
//! `docs/spec/delegation-circuits.md` §2 is what this suite restates: the 51-word frame,
//! the anchor's two tuples, the one-hot round selector, the five
//! transformations and the two frame-pointer checks that must be in the emitted
//! artifact rather than in a comment.
//!
//! **There is no forward pass here, and since S26d there cannot be.** This
//! family carries the `RANGE16` and `XOR8` channels, whose tables each need
//! sixteen variables, so its circuit cannot be built at the reduced height a
//! whole-shard forward pass would need — `family_circuit` returns `None` below
//! `2^16`. So the arithmetic is checked row by row, exactly as
//! `crates/checker/tests/mod_mul.rs` and `ec_add.rs` check theirs: each row is
//! built from **`u64` host arithmetic in this file** and evaluated alone through
//! `checker::violated_relations`, its row-local scratch computed by
//! `gkr::gate_values`.
//!
//! Two readings, because this circuit has two halves:
//!
//! - the **gates** — the frame's addressing and bounds, the selector, the byte
//!   decomposition of every frame word in both directions, and the rotation —
//!   through `checker::violated_relations`;
//! - the **obligations** — every Boolean operation of the round — through
//!   [`violated_xor8`], which states what the `XOR8` table means (`e0` and `e1`
//!   are bytes and `e2` is their XOR) rather than looking a row up in it. That
//!   is the native reading of the obligation, the same statement LogUp proves,
//!   and it is the only thing in the fast gate that says the 1,020 obligations
//!   of a row are the right 1,020: nine tenths of this circuit is in them.
//!
//! The round this file computes is written from `docs/spec/delegation-circuits.md` §2
//! in `u64` primitives and shares no line with `crates/prover`'s fill or
//! `crates/emulator`'s executor, so a circuit stating anything but a Keccak
//! round would reject an honest witness. [`the_round_is_the_executors`] closes
//! the loop to the outside: it holds this file's round equal to
//! `emulator::keccak_round`, which `crates/emulator/tests/keccak.rs` holds —
//! twenty-four at a time — to `tiny-keccak`.
//!
//! Every negative control corrupts one cell of an otherwise honest witness, or
//! supplies an honest witness for a claim the circuit must refuse, and names the
//! relation or the obligation that must catch it.

use constants::{challenge_slot, delegation, guest_memory, keccak as k, memory as mem};
use constraints::keccak;
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress};
use field::Fr;
use gkr::{gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use poly::{MultilinearPoly, PolyBacking};

#[path = "../../prover/tests/common/mod.rs"]
mod common;

/// The circuit's own height. `RANGE16`'s table and `XOR8`'s each need sixteen
/// variables, which is the floor; the family is at `2^18`, and this tracks it
/// rather than the floor because `the_fill_satisfies_every_gate_and_every_obligation`
/// builds a program config from `common::keccak_params` and fills `1 << VARS`
/// rows of it — the two reading different heights would be a fill that matches
/// no config.
const VARS: u32 = 18;

/// The rows this suite builds and evaluates: one complete permutation's 24
/// rounds, two corner rows, and padding to a power of two. The other 262,112
/// rows of the circuit are never materialized — a relation is row-local, so one
/// row is all an evaluation needs.
const ROWS: usize = 32;

/// Rows the honest set fills: 24 rounds of one permutation, then the two
/// corners.
const LIVE_ROWS: usize = k::ROUNDS + 2;

/// One invocation as a witness builder sees it: the round, and the state the
/// frame holds when the call is made.
#[derive(Clone, Copy)]
struct Invocation {
    cycle: u64,
    base: u32,
    round: usize,
    state: [u64; k::LANES],
}

/// One round's intermediates, computed here from `u64` primitives and from
/// nothing this repository's prover or executor owns.
///
/// `docs/spec/delegation-circuits.md` §2 in nine stages: theta's parity chain, its
/// masked copy, `D`, `A'`, rho's masked copy, `B` after rho and pi, chi's
/// helper and output, and iota's four bytes.
struct Round {
    parity: [[u64; 4]; 5],
    c_mask: [u64; 5],
    theta_d: [u64; 5],
    theta_a: [u64; k::LANES],
    rho_mask: [u64; k::LANES],
    rho_out: [u64; k::LANES],
    chi_and: [u64; k::LANES],
    chi_out: [u64; k::LANES],
    out: [u64; k::LANES],
}

/// Each byte of a `u64` masked to its top `s` bits.
fn byte_mask(s: u32) -> u64 {
    let byte = (256u64 - (1u64 << (8 - s))) as u8;
    u64::from_le_bytes([byte; 8])
}

/// Lane `i`'s rho rotation, read from `constants::keccak` and not restated.
fn rotation(i: usize) -> u32 {
    k::ROTATIONS[i / 5][i % 5]
}

fn round_of(state: &[u64; k::LANES], round: usize) -> Round {
    let mut parity = [[0u64; 4]; 5];
    for (x, chain) in parity.iter_mut().enumerate() {
        let mut acc = state[x];
        for (s, slot) in chain.iter_mut().enumerate() {
            acc ^= state[x + 5 * (s + 1)];
            *slot = acc;
        }
    }
    let c: [u64; 5] = core::array::from_fn(|x| parity[x][3]);
    let c_mask: [u64; 5] = core::array::from_fn(|x| c[x] ^ byte_mask(1));
    let theta_d: [u64; 5] =
        core::array::from_fn(|x| c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1));
    let theta_a: [u64; k::LANES] = core::array::from_fn(|i| state[i] ^ theta_d[i % 5]);
    let rho_mask: [u64; k::LANES] = core::array::from_fn(|i| match rotation(i) % 8 {
        0 => 0,
        s => theta_a[i] ^ byte_mask(s),
    });
    let mut rho_out = [0u64; k::LANES];
    for x in 0..5 {
        for y in 0..5 {
            rho_out[y + 5 * ((2 * x + 3 * y) % 5)] =
                theta_a[x + 5 * y].rotate_left(k::ROTATIONS[y][x]);
        }
    }
    let chi_and: [u64; k::LANES] = core::array::from_fn(|i| {
        let (x, y) = (i % 5, i / 5);
        rho_out[(x + 1) % 5 + 5 * y] ^ rho_out[(x + 2) % 5 + 5 * y]
    });
    let chi_out: [u64; k::LANES] = core::array::from_fn(|i| {
        let (x, y) = (i % 5, i / 5);
        rho_out[i] ^ (!rho_out[(x + 1) % 5 + 5 * y] & rho_out[(x + 2) % 5 + 5 * y])
    });
    let mut out = chi_out;
    out[0] ^= k::ROUND_CONSTANTS[round];
    Round {
        parity,
        c_mask,
        theta_d,
        theta_a,
        rho_mask,
        rho_out,
        chi_and,
        chi_out,
        out,
    }
}

fn lanes_to_words(lanes: &[u64; k::LANES]) -> [u32; k::STATE_WORDS] {
    core::array::from_fn(|j| (lanes[j / 2] >> (32 * (j % 2))) as u32)
}

/// Byte `b` of a lane, which is the unit every column of this circuit holds.
fn byte(lane: u64, b: usize) -> u64 {
    (lane >> (8 * b)) & 0xff
}

fn column(values: Vec<u64>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(
        values.into_iter().map(Fr::from_u64).collect(),
    ))
}

/// The honest witness of `live`, padded to [`ROWS`] with zero rows.
///
/// Every cell follows `docs/spec/delegation-circuits.md` §2: the frame word at
/// `base + 4j` read at the previous cycle's slot 0 and written at this one's,
/// the round selector, the round constant's four bytes, and the nine byte-wide
/// stages of the round.
fn witness(live: &[Invocation]) -> Vec<(PolyAddress, MultilinearPoly)> {
    let rounds: Vec<Round> = live.iter().map(|i| round_of(&i.state, i.round)).collect();
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    let mut push = |address: PolyAddress, of: &dyn Fn(usize, &Invocation, &Round) -> u64| {
        let values = (0..ROWS)
            .map(|r| match live.get(r) {
                Some(i) => of(r, i, &rounds[r]),
                None => 0,
            })
            .collect();
        out.push((address, column(values)));
    };
    push(keccak::CYCLE, &|_, i, _| i.cycle);
    push(keccak::LIVE, &|_, _, _| 1);
    push(keccak::BASE, &|_, i, _| i.base as u64);
    push(keccak::ANCHOR_VALUE, &|_, _, _| 0);

    // Frame word 0 is the round, read and written unchanged; the 50 state words
    // are read before the round and written after it.
    let read_word = move |j: usize, i: &Invocation| -> u64 {
        match j {
            k::ROUND_WORD => i.round as u64,
            _ => lanes_to_words(&i.state)[j - k::STATE_WORD] as u64,
        }
    };
    let written_word = move |j: usize, i: &Invocation, w: &Round| -> u64 {
        match j {
            k::ROUND_WORD => i.round as u64,
            _ => lanes_to_words(&w.out)[j - k::STATE_WORD] as u64,
        }
    };
    for j in 0..k::FRAME_WORDS {
        push(keccak::word(j, keccak::WORD_ADDR), &move |_, i, _| {
            i.base as u64 + 4 * j as u64
        });
        // The read this word consumed: the previous cycle's frame write, which
        // for a chained permutation is the previous round's. Row 0 reads the
        // guest's own store, whose timestamp this suite puts one cycle earlier
        // too — nothing row-local distinguishes them, and the gap is what
        // matters.
        push(keccak::word(j, keccak::WORD_READ_TS), &|_, i, _| {
            mem::TS_STEP * (i.cycle - 1) + delegation::FRAME_DELTA
        });
        push(keccak::word(j, keccak::WORD_READ_VALUE), &move |_, i, _| {
            read_word(j, i)
        });
        push(
            keccak::word(j, keccak::WORD_WRITE_VALUE),
            &move |_, i, w| written_word(j, i, w),
        );
    }
    // The gap, `4·cycle + FRAME_DELTA − read_ts − 1`, as two `RANGE16` chunks a
    // word; the low part is derived.
    for j in 0..k::FRAME_WORDS {
        for c in 0..constraints::delegation::GAP_CHUNKS {
            push(keccak::gap_chunk(j, c), &move |_, i, _| {
                let gap = mem::TS_STEP * i.cycle + delegation::FRAME_DELTA
                    - (mem::TS_STEP * (i.cycle - 1) + delegation::FRAME_DELTA)
                    - 1;
                (gap >> (16 * (c as u32 + 1))) & 0xffff
            });
        }
    }
    let low = |i: &Invocation| ((i.base - guest_memory::RAM_ORIGIN) / 4) as u64;
    let room = |i: &Invocation| (1u64 << 31) - k::FRAME_BYTES as u64 - i.base as u64;
    push(keccak::base_low(), &move |_, i, _| low(i));
    push(keccak::base_low_hi(), &move |_, i, _| low(i) >> 16);
    push(keccak::base_room(), &move |_, i, _| room(i));
    push(keccak::base_room_hi(), &move |_, i, _| room(i) >> 16);

    for r in 0..k::ROUNDS {
        push(keccak::round_sel(r), &move |_, i, _| {
            u64::from(i.round == r)
        });
    }
    for (t, b) in k::IOTA_BYTES.iter().enumerate() {
        push(keccak::rc(t), &move |_, i, _| {
            byte(k::ROUND_CONSTANTS[i.round], *b)
        });
    }
    for i in 0..k::LANES {
        for b in 0..8 {
            push(keccak::state_in(i, b), &move |_, inv, _| {
                byte(inv.state[i], b)
            });
        }
    }
    for x in 0..5 {
        for b in 0..8 {
            for s in 0..4 {
                push(keccak::parity(x, b, s), &move |_, _, w| {
                    byte(w.parity[x][s], b)
                });
            }
        }
    }
    for x in 0..5 {
        for b in 0..8 {
            push(keccak::c_mask(x, b), &move |_, _, w| byte(w.c_mask[x], b));
        }
    }
    for x in 0..5 {
        for b in 0..8 {
            push(keccak::theta_d(x, b), &move |_, _, w| byte(w.theta_d[x], b));
        }
    }
    for i in 0..k::LANES {
        for b in 0..8 {
            push(keccak::theta_a(i, b), &move |_, _, w| byte(w.theta_a[i], b));
        }
    }
    for i in 0..k::LANES {
        if rotation(i).is_multiple_of(8) {
            continue;
        }
        for b in 0..8 {
            push(keccak::rho_mask(i, b), &move |_, _, w| {
                byte(w.rho_mask[i], b)
            });
        }
    }
    for i in 0..k::LANES {
        for b in 0..8 {
            push(keccak::rho_out(i, b), &move |_, _, w| byte(w.rho_out[i], b));
        }
    }
    for i in 0..k::LANES {
        for b in 0..8 {
            push(keccak::chi_and(i, b), &move |_, _, w| byte(w.chi_and[i], b));
        }
    }
    for i in 0..k::LANES {
        for b in 0..8 {
            push(keccak::chi_out(i, b), &move |_, _, w| byte(w.chi_out[i], b));
        }
    }
    for (t, b) in k::IOTA_BYTES.iter().enumerate() {
        push(keccak::iota_out(t), &move |_, _, w| byte(w.out[0], *b));
    }
    // A channel's multiplicity is `crates/trace`'s and no gate reads it — but
    // `a.committed()` names it, so the column has to exist.
    out.push((keccak::range16_multiplicity(), column(vec![0; ROWS])));
    out.push((keccak::xor8_multiplicity(), column(vec![0; ROWS])));
    out
}

/// The memory challenges, the channels' `g` and the `beta` powers their tuple
/// positions read.
fn challenges_for(a: &CircuitArtifact) -> ExternalChallenges {
    let mut ch = ExternalChallenges::new();
    for (slot, value) in [
        (challenge_slot::MEM_GAMMA, 3u64),
        (challenge_slot::MEM_ALPHA_ADDR, 5),
        (challenge_slot::MEM_ALPHA_TS, 7),
        (challenge_slot::MEM_ALPHA_VAL, 11),
    ] {
        ch.insert(slot, Fr::from_u64(value));
    }
    insert_lookup_challenges(&mut ch, Fr::from_u64(13), Fr::from_u64(17), a);
    ch
}

fn corrupt(
    mut columns: Vec<(PolyAddress, MultilinearPoly)>,
    address: PolyAddress,
    row: usize,
    value: Fr,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let slot = columns
        .iter_mut()
        .find(|(a, _)| *a == address)
        .unwrap_or_else(|| panic!("{address} is not a committed column"));
    let mut values: Vec<Fr> = (0..ROWS).map(|r| slot.1.get(r)).collect();
    values[row] = value;
    slot.1 = MultilinearPoly::new(PolyBacking::Fr(values));
    columns
}

/// One cell of one column, as the row sees it.
fn cell(columns: &[(PolyAddress, MultilinearPoly)], address: PolyAddress, row: usize) -> Fr {
    columns
        .iter()
        .find(|(a, _)| *a == address)
        .unwrap_or_else(|| panic!("{address} is not a committed column"))
        .1
        .get(row)
}

/// One row of a column set as a witness row of `a`, its scratch computed
/// row-locally by the engine's own gate kernel.
fn witness_row(
    a: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    row: usize,
) -> checker::WitnessRow {
    let committed: Vec<Fr> = a
        .committed()
        .into_iter()
        .map(|address| cell(columns, address, row))
        .collect();
    let virtuals: Vec<Fr> = a
        .virtuals
        .iter()
        .map(|(kind, _)| virtual_at_row(*kind, row))
        .collect();
    let ch = challenges_for(a);
    let mut scratch = vec![Fr::ZERO; a.scratch.len()];
    let mut lower = committed.clone();
    for k in 0..a.depth() {
        if a.layers[k].halving {
            break;
        }
        let v: &[Fr] = if k == 0 { &virtuals } else { &[] };
        let values = gate_values(a, k, &lower, &[], v, &ch);
        let produced = values[..a.layers[k].producing.len()].to_vec();
        for (j, value) in produced.iter().enumerate() {
            let address = PolyAddress::Inner {
                layer: k as u32 + 1,
                offset: j as u32,
            };
            let slot = a
                .scratch
                .iter()
                .position(|s| s.address == address)
                .expect("every inner column has a scratch slot");
            scratch[slot] = *value;
        }
        lower = produced;
    }
    checker::WitnessRow {
        committed,
        row,
        scratch,
    }
}

/// The relation the corrupted row must break, or a panic saying nothing did.
fn refusal(a: &CircuitArtifact, columns: Vec<(PolyAddress, MultilinearPoly)>) -> String {
    for row in 0..ROWS {
        let violated =
            checker::violated_relations(a, &witness_row(a, &columns, row), &challenges_for(a));
        if let Some(name) = violated.first() {
            return name.clone();
        }
    }
    panic!("the corrupted witness satisfies every gate")
}

/// Every relation every row satisfies, or a panic naming the first that does
/// not.
fn assert_every_row_holds(a: &CircuitArtifact, columns: &[(PolyAddress, MultilinearPoly)]) {
    for row in 0..ROWS {
        let violated =
            checker::violated_relations(a, &witness_row(a, columns, row), &challenges_for(a));
        assert!(violated.is_empty(), "row {row} breaks {violated:?}");
    }
}

// ---------------------------------------------------------------------------
// The XOR8 channel, read natively
// ---------------------------------------------------------------------------

/// A field element as the byte it must be, or `None` if it is not one.
fn as_byte(x: Fr) -> Option<u64> {
    let bytes = x.to_bytes();
    match bytes[1..].iter().all(|b| *b == 0) {
        true => Some(bytes[0] as u64),
        false => None,
    }
}

/// One tuple expression of a lookup, evaluated over one row.
fn expression(e: &GateDef, columns: &[(PolyAddress, MultilinearPoly)], row: usize) -> Fr {
    let GateDef::Linear { terms, constant } = e else {
        panic!("a lookup expression is a Linear gate")
    };
    let Coeff::Literal(mut acc) = *constant else {
        panic!("a lookup expression's constant is a literal")
    };
    for (c, address) in terms {
        let Coeff::Literal(c) = c else {
            panic!("a lookup expression's coefficient is a literal")
        };
        acc += *c * cell(columns, *address, row);
    }
    acc
}

/// Every `XOR8` obligation of `a` that row `row` does not satisfy, by name.
///
/// This states what the table **is** — `(a, b, a ^ b)` over every pair of bytes
/// — rather than looking a row up in it, which makes it the native reading of
/// the obligation and the same statement LogUp proves: on a row whose selector
/// is 0 the gated tuple is the all-zero one, which is a real entry, so a
/// padding row satisfies every obligation by construction.
///
/// It is the only reading of the round's semantics in the fast gate. Nine
/// tenths of this circuit is its 1,020 obligations, and no gate anywhere reads
/// the columns they pin.
fn violated_xor8(
    a: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    row: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    for l in &a.lookups {
        if l.channel != constants::lookup_channel::XOR8 {
            continue;
        }
        if cell(columns, l.selector, row) == Fr::ZERO {
            continue;
        }
        let values: Vec<Option<u64>> = l
            .tuple
            .iter()
            .map(|e| as_byte(expression(e, columns, row)))
            .collect();
        let held = match values.as_slice() {
            [Some(x), Some(y), Some(z)] => *z == (*x ^ *y),
            _ => false,
        };
        if !held {
            out.push(l.name.clone());
        }
    }
    out
}

/// Every `XOR8` obligation every row satisfies.
fn assert_every_obligation_holds(a: &CircuitArtifact, columns: &[(PolyAddress, MultilinearPoly)]) {
    for row in 0..ROWS {
        let violated = violated_xor8(a, columns, row);
        assert!(violated.is_empty(), "row {row} breaks {violated:?}");
    }
}

/// The one `XOR8` obligation the corrupted witness breaks, or a panic.
fn xor8_refusal(a: &CircuitArtifact, columns: &[(PolyAddress, MultilinearPoly)]) -> Vec<String> {
    for row in 0..ROWS {
        let violated = violated_xor8(a, columns, row);
        if !violated.is_empty() {
            return violated;
        }
    }
    panic!("the corrupted witness satisfies every XOR8 obligation")
}

// ---------------------------------------------------------------------------
// The honest set
// ---------------------------------------------------------------------------

/// A base pointer, one frame apart from the last.
fn base(k: u32) -> u32 {
    guest_memory::RAM_ORIGIN + 4 * 1024 * k
}

/// The 26 live invocations: **one whole permutation**, round 0 through 23, each
/// reading the state the one before it wrote and all at one frame base — which
/// is the S26d shape, the chain being the frame's own RAM history — then two
/// corners.
///
/// The corners are the two states whose byte masks are degenerate: the all-zero
/// state, whose every intermediate is 0 until iota puts the round constant into
/// lane `(0,0)`, and the all-ones state, where every mask lookup sees `0xff` and
/// every rotation carries every bit across a byte boundary.
fn honest() -> Vec<Invocation> {
    let mut rng = test_support::Rng::new(0x5236_0526);
    let mut state: [u64; k::LANES] = core::array::from_fn(|_| rng.next_u64());
    let mut live: Vec<Invocation> = Vec::with_capacity(LIVE_ROWS);
    for round in 0..k::ROUNDS {
        live.push(Invocation {
            cycle: 7 + round as u64,
            base: base(1),
            round,
            state,
        });
        state = round_of(&state, round).out;
    }
    live.push(Invocation {
        cycle: 101,
        base: base(3),
        round: 0,
        state: [0; k::LANES],
    });
    live.push(Invocation {
        cycle: 103,
        base: base(5),
        round: k::ROUNDS - 1,
        state: [u64::MAX; k::LANES],
    });
    live
}

/// The row of the honest set claiming `round` inside the permutation.
fn row_of(round: usize) -> usize {
    round
}

// ---------------------------------------------------------------------------
// The circuit
// ---------------------------------------------------------------------------

#[test]
fn the_circuit_keeps_every_rule() {
    let a = keccak::artifact(VARS);
    a.validate().expect("the circuit is a circuit");
    checker::check_laws(&a).expect("the standalone validators agree");
    checker::check_padding(&a).expect("the padding contract holds");
    checker::check_padding_identity(&a).expect("the padding identity clause holds");
    constraints::memory::check_memory(&a).expect("the memory provenance rules hold");
    checker::check_lookup_discharge(&a, &keccak::channels())
        .expect("every obligation is discharged exactly once, in its own channel");
}

/// The shape `docs/spec/delegation-circuits.md` §2 accounts for.
///
/// A digest that moves says only *that* something moved; these numbers say what.
/// `crates/constraints/tests/vectors/keccak.txt` carries the same counts beside
/// the digest and `tools/kat-gen` writes them from the same constructor — this
/// is the third reading, and the one a reviewer can compare against the page.
#[test]
fn the_shape_is_the_manifests() {
    let a = keccak::artifact(VARS);
    assert_eq!(a.memory.len(), 4 + 4 * k::FRAME_WORDS);
    assert_eq!(a.memory.len(), keccak::MEMORY_COLUMNS);
    assert_eq!(a.witness.len(), keccak::WITNESS_COLUMNS);
    assert!(a.setup.is_empty(), "no setup column, so nothing to bind");
    assert_eq!(a.virtuals.len(), 4, "range16, and XOR8's three columns");

    // The two channels, and the obligation counts that decide the family's
    // cost: 210 on `RANGE16` — four a frame gap, three a base decomposition —
    // and 1,020 on `XOR8`, three short of the 1,024-leaf fraction tree's
    // capacity (`docs/spec/delegation-circuits.md` §2).
    let count = |channel: u32| a.lookups.iter().filter(|l| l.channel == channel).count();
    assert_eq!(count(constants::lookup_channel::RANGE16), 210);
    assert_eq!(count(constants::lookup_channel::XOR8), 1_020);
    assert_eq!(a.lookups.len(), 1_230);
    assert_eq!((1_020 + 1usize).next_power_of_two(), 1_024);

    // The circuit is **flat**: nothing above gate list 0 but the two memory
    // product trees, the two channels' fraction trees and the halving phase. So
    // there is exactly one list of enforcing gates, and every relation of every
    // later list produces a tree column.
    assert!(
        a.layers[1..].iter().all(|l| l.enforcing.is_empty()),
        "a flat circuit enforces on gate list 0 alone"
    );
    let enforcing = a.layers[0].enforcing.len();
    assert_eq!(
        enforcing,
        // the frame: live_boolean, 51 addr_w, base_aligned, base_in_window
        1 + k::FRAME_WORDS + 2
            // the selector: 24 booleanity, round_rule, one_round_a_live_row,
            // and four round-constant bytes
            + k::ROUNDS + 2 + k::IOTA_BYTES.len()
            // the frame's values: writes_back_w0, and a decode each way a word
            + 1 + 2 * k::STATE_WORDS
            // rho and pi: one gate a byte of the state
            + k::LANES * 8,
        "the enforcing gates are the manifest's"
    );
    assert_eq!(enforcing, 385);

    // Four outputs before S26d, six now: the two memory roots and a `(num, den)`
    // pair per channel, in `channels()` order.
    assert_eq!(a.outputs.len(), 6);
    // One gate list, ten row-wise reductions — the XOR8 tree's depth — and one
    // halving list a variable.
    assert_eq!(a.depth(), 1 + 10 + VARS as usize);
}

/// What a height does and does not move.
///
/// A height is `trace_vars`: it adds one halving list per variable, carrying one
/// node per output, and it changes no gate and no obligation. `2^16` is this
/// family's only admissible height — `family_circuit` refuses less and the menu's
/// next entry is four times the cost — but the artifact is data and builds at
/// either, so the property is checkable.
#[test]
fn a_height_moves_only_the_halving_layers() {
    let (low, high) = (keccak::artifact(16), keccak::artifact(18));
    assert_eq!(low.memory, high.memory);
    assert_eq!(low.witness, high.witness);
    assert_eq!(low.lookups.len(), high.lookups.len());
    assert_eq!(
        low.layers[0].enforcing.len(),
        high.layers[0].enforcing.len()
    );
    assert_eq!(high.depth() - low.depth(), 2);
    assert_eq!(
        high.relations.len() - low.relations.len(),
        2 * low.outputs.len()
    );
}

/// The one height, and both channels' floors.
#[test]
fn the_channels_set_the_family_floor() {
    use constants::family::KECCAK_F as KEC;
    assert!(constraints::family_circuit(KEC, 8).is_none());
    assert!(constraints::family_circuit(KEC, 14).is_none());
    assert!(constraints::family_circuit(KEC, 16).is_some());
    assert_eq!(
        constraints::lookup::table_vars(constants::lookup_channel::XOR8),
        16,
        "the XOR8 table is 65,536 rows, so the floor is 16 without RANGE16 too"
    );
}

// ---------------------------------------------------------------------------
// The round
// ---------------------------------------------------------------------------

/// The round this file computes is the round the executor computes.
///
/// This is the one line that ties the suite to the outside. Everything below
/// checks the circuit against `round_of`, which is written here from the spec;
/// `crates/emulator/tests/keccak.rs` holds `emulator::keccak_round` — twenty-four
/// at a time — to `tiny-keccak`. Without this the two chains would never meet.
#[test]
fn the_round_is_the_executors() {
    let mut rng = test_support::Rng::new(0x0d26_5236);
    for round in 0..k::ROUNDS {
        let start: [u64; k::LANES] = core::array::from_fn(|_| rng.next_u64());
        let mut theirs = start;
        emulator::keccak_round(&mut theirs, round);
        assert_eq!(round_of(&start, round).out, theirs, "round {round}");
    }
}

/// **Acceptance: the circuit computes one Keccak round, on every round.**
///
/// The witness is built from `u64` arithmetic in this file and from nothing the
/// prover or the executor owns. If the circuit stated any other relation — a
/// wrong rho offset, a wrong pi map, a dropped round constant, a rotation weight
/// off by a factor of two — an honest witness would fail its own gates or its own
/// obligations. Twenty-four rows are one whole permutation, so every round
/// constant and every selector is exercised; two corner rows and six padding
/// rows follow, so the padding row's own satisfaction is part of what passes
/// here.
#[test]
fn an_honest_witness_satisfies_every_gate_and_obligation() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    assert_every_row_holds(&a, &columns);
    assert_every_obligation_holds(&a, &columns);
}

/// The 24 rows are one permutation: round `r`'s written state is round `r + 1`'s
/// read state, at one frame base.
///
/// This is what the memory multiset proves in a real block, and what makes 24
/// invocations a keccak-f rather than 24 unrelated rounds
/// (`docs/spec/delegation-circuits.md` §2). Here it is a property of the honest set,
/// stated so a reader can see the chain the proof relies on.
#[test]
fn the_twenty_four_rows_chain_through_the_frame() {
    let columns = witness(&honest());
    for round in 0..k::ROUNDS - 1 {
        for j in k::STATE_WORD..k::FRAME_WORDS {
            assert_eq!(
                cell(&columns, keccak::word(j, keccak::WORD_WRITE_VALUE), round),
                cell(
                    &columns,
                    keccak::word(j, keccak::WORD_READ_VALUE),
                    round + 1
                ),
                "round {round} word {j}"
            );
            assert_eq!(
                cell(&columns, keccak::word(j, keccak::WORD_ADDR), round),
                cell(&columns, keccak::word(j, keccak::WORD_ADDR), round + 1),
                "one frame, one base"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The negative controls: the gates
// ---------------------------------------------------------------------------

/// A state byte that is not the frame word's: `input_w{j}` is the decode and the
/// byte's 32-bit bound at once.
#[test]
fn a_changed_state_byte_is_refused() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let row = row_of(3);
    let was = cell(&columns, keccak::state_in(0, 0), row);
    assert_eq!(
        refusal(
            &a,
            corrupt(columns, keccak::state_in(0, 0), row, was + Fr::ONE)
        ),
        format!("input_w{}", k::STATE_WORD)
    );
}

/// A written word that is not the round's output: `output_w{j}`.
#[test]
fn a_changed_written_word_is_refused() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let row = row_of(5);
    let j = k::STATE_WORD + 7;
    let was = cell(&columns, keccak::word(j, keccak::WORD_WRITE_VALUE), row);
    assert_eq!(
        refusal(
            &a,
            corrupt(
                columns,
                keccak::word(j, keccak::WORD_WRITE_VALUE),
                row,
                was + Fr::ONE
            )
        ),
        format!("output_w{j}")
    );
}

/// A round word the invocation rewrote: `writes_back_w0`.
///
/// The round word is the one frame word this family does not compute, and the
/// guest's own loop is what advances it. An invocation that could rewrite it
/// would be handing the next round a number nobody stored.
#[test]
fn a_round_word_the_call_rewrote_is_refused() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let row = row_of(9);
    let was = cell(
        &columns,
        keccak::word(k::ROUND_WORD, keccak::WORD_WRITE_VALUE),
        row,
    );
    assert_eq!(
        refusal(
            &a,
            corrupt(
                columns,
                keccak::word(k::ROUND_WORD, keccak::WORD_WRITE_VALUE),
                row,
                was + Fr::ONE
            )
        ),
        format!("writes_back_w{}", k::ROUND_WORD)
    );
}

/// A round selector the frame word does not name: `round_rule`.
///
/// A row claiming a round other than the frame's would XOR the wrong constant
/// into lane `(0,0)` — correct arithmetic and the wrong answer, which is exactly
/// the failure the selector exists to make impossible.
#[test]
fn a_selector_the_round_word_does_not_name_is_refused() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let row = row_of(11);
    assert_eq!(
        refusal(&a, corrupt(columns, keccak::round_sel(11), row, Fr::ZERO)),
        "round_rule"
    );
}

/// Two selectors at once, spelling a third round: `one_round_a_live_row`.
///
/// `round_rule` alone does not refuse this and cannot — the codes are `0..24`, so
/// **every** pair sums to another round's word: `1 + 2 = 3`. A row claiming
/// rounds 1 and 2 spells the word of a row claiming round 3, and the sum gate is
/// the only thing that refuses it. This is `mod_mul::one_modulus_a_live_row`'s
/// argument at its sharpest, the codes here being consecutive from zero rather
/// than four spaced values.
#[test]
fn two_rounds_at_once_is_refused() {
    let a = keccak::artifact(VARS);
    let mut columns = witness(&honest());
    let row = row_of(3);
    for (r, value) in [(3usize, Fr::ZERO), (1, Fr::ONE), (2, Fr::ONE)] {
        columns = corrupt(columns, keccak::round_sel(r), row, value);
    }
    assert_eq!(refusal(&a, columns), "one_round_a_live_row");
}

/// A round constant that is not the selected literal: `rc{t}_rule`.
///
/// The four `rc` columns are the only place a round constant exists in the
/// witness, and nothing about them is a frame word. Without this gate a prover
/// would choose the constant freely and the selector would be decoration.
#[test]
fn a_round_constant_that_is_not_the_selected_literal_is_refused() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let row = row_of(7);
    let was = cell(&columns, keccak::rc(0), row);
    assert_eq!(
        refusal(&a, corrupt(columns, keccak::rc(0), row, was + Fr::ONE)),
        "rc0_rule"
    );
}

/// A rotated byte that is not the rotation: `rho_pi_l{i}_b{j}`.
///
/// The rotation is the family's most intricate relation — a literal-weighted
/// combination of a byte and its masked copy, with a constant riding `live` — and
/// it is where a wrong weight, a wrong byte index or a wrong `2^{s-9}` would
/// hide. Every one of the 25 lanes is checked by the honest witness; this names
/// the gate.
#[test]
fn a_changed_rotated_byte_is_refused() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let row = row_of(13);
    let was = cell(&columns, keccak::rho_out(7, 3), row);
    assert_eq!(
        refusal(
            &a,
            corrupt(columns, keccak::rho_out(7, 3), row, was + Fr::ONE)
        ),
        "rho_pi_l7_b3"
    );
}

/// A frame word at the wrong address: `addr_w{j}`.
#[test]
fn a_frame_word_off_its_base_is_refused() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let row = row_of(2);
    let j = k::STATE_WORD + 4;
    let was = cell(&columns, keccak::word(j, keccak::WORD_ADDR), row);
    assert_eq!(
        refusal(
            &a,
            corrupt(
                columns,
                keccak::word(j, keccak::WORD_ADDR),
                row,
                was + Fr::from_u64(4)
            )
        ),
        format!("addr_w{j}")
    );
}

/// A misaligned frame base has no witness at all: `base_aligned` is a
/// **decomposition** — `base = RAM_ORIGIN + 4·base_low` with `base_low` bounded
/// — and not an equation over `Fr`, where 4 is a unit and every base would have
/// a quotient.
///
/// The twin moves the base **and all 51 frame addresses with it**, which is how a
/// prover holding a misaligned frame would build it: with the addresses left
/// where they were, `addr_w0` refuses the row first and says nothing about
/// alignment.
#[test]
fn a_misaligned_base_is_refused() {
    let a = keccak::artifact(VARS);
    let mut columns = witness(&honest());
    let row = row_of(4);
    let two = Fr::from_u64(2);
    let was = cell(&columns, keccak::BASE, row);
    columns = corrupt(columns, keccak::BASE, row, was + two);
    for j in 0..k::FRAME_WORDS {
        let address = keccak::word(j, keccak::WORD_ADDR);
        let was = cell(&columns, address, row);
        columns = corrupt(columns, address, row, was + two);
    }
    assert_eq!(refusal(&a, columns), "base_aligned");
}

// ---------------------------------------------------------------------------
// The negative controls: the obligations
// ---------------------------------------------------------------------------

/// Four of the round's stages are pinned by the `XOR8` channel **alone**: no gate
/// anywhere reads `parity`, `c_mask`, `theta_d` or `chi_and`, so a wrong value
/// breaks no relation and is refused by the obligation that names it.
///
/// That is the statement of S26d's architecture in one test: the round **is** its
/// obligations, and the gates only tie those to the frame. The cells here are one
/// per stage, so a stage whose obligation was dropped or misrouted shows up as a
/// corruption nothing catches.
#[test]
fn a_round_stage_no_gate_reads_is_refused_by_the_channel_alone() {
    let a = keccak::artifact(VARS);
    let honest_columns = witness(&honest());
    let row = row_of(6);
    let cases: [(PolyAddress, &str); 4] = [
        (keccak::parity(2, 1, 0), "parity_x2_b1_s0_xor"),
        (keccak::c_mask(3, 2), "c_mask_x3_b2_xor"),
        (keccak::theta_d(4, 5), "theta_d_x4_b5_xor"),
        (keccak::chi_and(17, 0), "chi_and_l17_b0_xor"),
    ];
    for (address, obligation) in cases {
        let was = cell(&honest_columns, address, row);
        let columns = corrupt(honest_columns.clone(), address, row, was + Fr::ONE);
        for r in 0..ROWS {
            let violated =
                checker::violated_relations(&a, &witness_row(&a, &columns, r), &challenges_for(&a));
            assert!(
                violated.is_empty(),
                "{address} broke the gate {violated:?}, so the channel is not the only bound"
            );
        }
        assert!(
            xor8_refusal(&a, &columns).contains(&obligation.to_string()),
            "{address} is not refused by `{obligation}`"
        );
    }
}

/// The other stages are read by a gate **and** by the channel, and both see a
/// corruption. `theta_a` and `rho_mask` are the rotation's two operands, so the
/// gate that catches them is one of the 200 `rho_pi_l{i}_b{j}`; `chi_out` is what
/// a lane's frame words are written from, so the gate is `output_w{j}`.
///
/// Keeping this separate from the test above is the point: which stage a gate
/// reads is a property of the circuit's shape, and a stage moving from one list
/// to the other would be a real change in what pins it.
#[test]
fn a_round_stage_a_gate_reads_is_refused_twice() {
    let a = keccak::artifact(VARS);
    let honest_columns = witness(&honest());
    let row = row_of(6);
    for (address, obligation) in [
        (keccak::theta_a(9, 6), "theta_a_l9_b6_xor"),
        (keccak::rho_mask(12, 7), "rho_mask_l12_b7_xor"),
    ] {
        let was = cell(&honest_columns, address, row);
        let columns = corrupt(honest_columns.clone(), address, row, was + Fr::ONE);
        let named = refusal(&a, columns.clone());
        assert!(
            named.starts_with("rho_pi_l"),
            "{address} is a rotation operand, and `{named}` is not a rotation gate"
        );
        assert!(xor8_refusal(&a, &columns).contains(&obligation.to_string()));
    }
    // `chi_out` at lane 21, byte 4: the high half of that lane's pair of frame
    // words, which is `STATE_WORD + 2·21 + 1`.
    let address = keccak::chi_out(21, 4);
    let was = cell(&honest_columns, address, row);
    let columns = corrupt(honest_columns.clone(), address, row, was + Fr::ONE);
    assert_eq!(
        refusal(&a, columns.clone()),
        format!("output_w{}", k::STATE_WORD + 2 * 21 + 1)
    );
    assert!(xor8_refusal(&a, &columns).contains(&"chi_out_l21_b4_xor".to_string()));
}

/// Iota's output is the channel's too, and it is the one stage a gate *does*
/// also read — `output_w{j}`, lane `(0,0)`'s two words being written from it.
#[test]
fn a_changed_iota_byte_is_refused() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let row = row_of(8);
    let was = cell(&columns, keccak::iota_out(0), row);
    let broken = corrupt(columns, keccak::iota_out(0), row, was + Fr::ONE);
    assert_eq!(
        refusal(&a, broken.clone()),
        format!("output_w{}", k::STATE_WORD)
    );
    assert!(xor8_refusal(&a, &broken).contains(&"iota_out_b0_xor".to_string()));
}

/// A gap chunk is refused by `RANGE16` **alone**: since S26d this family
/// range-checks rather than decomposing, so there is no `gap_w{j}` gate and the
/// obligations are the bound and the decomposition at once.
#[test]
fn a_changed_gap_chunk_is_refused_by_the_channel_alone() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let row = row_of(10);
    let broken = corrupt(columns, keccak::gap_chunk(3, 0), row, Fr::from_u64(2));
    for r in 0..ROWS {
        let violated =
            checker::violated_relations(&a, &witness_row(&a, &broken, r), &challenges_for(&a));
        assert!(
            violated.is_empty(),
            "a gap chunk broke the gate {violated:?}"
        );
    }
    let violated = checker::violated_lookups(&a, &witness_row(&a, &broken, row));
    assert!(
        violated.contains(&"gap3_lo_range".to_string()),
        "the gap's derived low part is what sees it: {violated:?}"
    );
}

/// The padding row is free where every gate and obligation carries `live`, and
/// **not** free where a gate is ungated.
///
/// The distinction is worth a test because a reviewer reading "the row mask
/// gates everything" would expect both halves to pass: a gap chunk and a base
/// halfword really are free, because the frame's gates carry the mask on every
/// product and the frame's obligations carry `live` as their selector; a state
/// byte is not, because `input_w{j}` is ungated and a padding row's words are 0.
#[test]
fn a_padding_row_is_free_only_where_the_mask_reaches() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let padding = LIVE_ROWS;
    assert_eq!(cell(&columns, keccak::LIVE, padding), Fr::ZERO);

    let mut free = columns.clone();
    for (address, value) in [
        (keccak::gap_chunk(5, 1), Fr::ONE),
        (keccak::base_room_hi(), Fr::ONE),
        (keccak::c_mask(0, 0), Fr::ONE),
    ] {
        free = corrupt(free, address, padding, value);
    }
    assert_every_row_holds(&a, &free);
    assert_every_obligation_holds(&a, &free);

    assert_eq!(
        refusal(
            &a,
            corrupt(columns, keccak::state_in(1, 3), padding, Fr::ONE)
        ),
        format!("input_w{}", k::STATE_WORD + 2)
    );
}

// ---------------------------------------------------------------------------
// The prover's own fill, over a real trace
// ---------------------------------------------------------------------------

/// **`prover::fill::keccak_f` writes the values this circuit's relations and
/// obligations expect**, over `guests/keccak-test`'s real execution.
///
/// Everything above builds its own columns, so nothing above can see a
/// disagreement between the fill's layout and the circuit's — and this family
/// has the most to get wrong there: nine byte-wide state blocks, a 24-column
/// one-hot selector, and a `rho_mask` block that is **22 lanes and not 25**. A
/// transposed lane or a byte read at the wrong offset is a silently wrong proof,
/// and `crates/prover/tests/fills.rs` only checks that every address is written
/// once.
///
/// It is the `crates/checker/tests/mem_fill.rs` pattern at a delegation family,
/// and it is here rather than in `prover`'s tests because only this crate can
/// see both `prover::family_fill` and `checker`'s evaluators. The only other
/// value-level reading of this fill is the `#[ignore]`d `prover::keccak` block
/// proof.
///
/// `trace::build_multiplicities` is part of what passes: it refuses a gated tuple
/// no row of the channel's table answers, which for `XOR8` means a byte that is
/// not a byte.
#[test]
fn the_fill_satisfies_every_gate_and_every_obligation() {
    let program = common::keccak_program();
    let archive = common::keccak_archive(&program);
    let circuit = constraints::family_circuit(constants::family::KECCAK_F, VARS)
        .expect("the registry has the keccak circuit");
    let a = &circuit.artifact;
    let fill = prover::family_fill(constants::family::KECCAK_F).expect("the family's fill");
    let source = prover::ShardSource::archived(
        &program,
        &archive,
        constants::family::KECCAK_F,
        0,
        1 << VARS,
        0,
    )
    .expect("the shard's rows");
    let mut columns = fill(&source).expect("the fill");
    let counts = trace::build_multiplicities(a, &columns, &circuit.channels)
        .unwrap_or_else(|e| panic!("keccak multiplicities: {e}"));
    columns.extend(counts);
    assert_eq!(
        columns.len(),
        a.committed().len(),
        "one column per committed address"
    );

    // Ten permutations of 24 rounds, and the profile counts them as invocations.
    let live = archive
        .family_traces()
        .delegation(constants::family::KECCAK_F)
        .expect("the archive has the delegation buffer")
        .len();
    assert_eq!(live as u64, common::KECCAK_INVOCATIONS);
    assert_eq!(
        live as u64,
        common::KECCAK_PERMUTATIONS * k::ROUNDS as u64,
        "24 invocations a permutation"
    );

    // Every live row, the two padding rows after them, and the shard's last.
    let rows: Vec<usize> = (0..live + 2).chain([(1usize << VARS) - 1]).collect();
    for row in rows {
        let w = witness_row(a, &columns, row);
        let violated = checker::violated_relations(a, &w, &challenges_for(a));
        assert!(violated.is_empty(), "row {row} breaks {violated:?}");
        let ranges = checker::violated_lookups(a, &w);
        assert!(ranges.is_empty(), "row {row} breaks {ranges:?}");
        let xor = violated_xor8(a, &columns, row);
        assert!(xor.is_empty(), "row {row} breaks {xor:?}");
    }

    // And the rounds really are 0..24 in order, which is the guest's loop seen
    // from the prover's side (`docs/spec/delegation-circuits.md` §2).
    for row in 0..live {
        let round = row % k::ROUNDS;
        assert_eq!(
            cell(&columns, keccak::round_sel(round), row),
            Fr::ONE,
            "invocation {row} claims round {round}"
        );
    }
}
