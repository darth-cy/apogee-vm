#![no_std]
#![no_main]
//! S-RECURSION's guest for the field memory: every `FR_OP` op — `DIGIT`'s
//! chain over a whole word among them — every `FQ_OP` op, a wrapping
//! subtraction, `(q − 1)²` and an indirect read and write among them — one
//! `P2_FIELD` duplex step at each of `n = 2, 1, 0`, and both `FIELD_IO` moves,
//! called by name over frames this guest writes itself
//! (`docs/spec/recursion.md` §2-§5).
//!
//! Every expectation is a **literal** — `7·11 = 77`, `150⁻¹`, three
//! permutations computed host-side by `transcript::poseidon2_permute` — and
//! every result leaves the field memory through an `EXPORT`, so the checks
//! read words in RAM and none of them is a second computation of the thing it
//! checks. The aliasing cases are here on purpose: an operation whose
//! destination is its own operand, and an `EQ` of a cell with itself.
//!
//! # The result
//!
//! The exit status, `a0`: one per check passed but the first, or `200 + i` on
//! the first that fails.

use constants::{field_io as io, fq_op as fq, fr_op as op};
use guest_sdk::recursion::{field_io, fq_op, fr_op, p2_field};
use guest_sdk::{entry, exit};

entry!(main);

/// `[op, d, a, b]`.
fn fr(code: u32, d: u32, a: u32, b: u32) {
    fr_op(&mut [code, d, a, b]);
}

/// `cell`'s value as eight little-endian words.
fn export(cell: u32) -> [u32; 8] {
    let mut words = [0u32; 8];
    field_io(&mut [io::EXPORT, cell, words.as_mut_ptr() as u32]);
    words
}

/// Four cells nothing writes: an element, read where an op ignores its `b`.
/// Every operand names an element, used or not, since an element's cells
/// share one read timestamp — which is also why an element's limbs are
/// exported only once nothing reads it whole again.
const ZERO_ELEMENT: u32 = 500;

/// `[op, d, a, b]` over elements.
fn fqe(word: u32, d: u32, a: u32, b: u32) {
    fq_op(&mut [word, d, a, b]);
}

/// The element at `cell`'s four limbs, each through an export.
fn element(cell: u32) -> [u64; 4] {
    core::array::from_fn(|k| {
        let w = export(cell + k as u32);
        w[0] as u64 | (w[1] as u64) << 32
    })
}

/// A cell holding the 128-bit integer whose words are `top` first.
fn wide(cell: u32, top: [u32; 4]) {
    fr(op::IMM, cell, 0, top[0]);
    for w in &top[1..] {
        fr(op::SHL, cell, cell, *w);
    }
}

/// `cell ← Σ_k words[k]·2^{32k}` mod p.
fn import(cell: u32, words: &[u32; 8]) {
    field_io(&mut [io::IMPORT, cell, words.as_ptr() as u32]);
}

/// A small value's words.
fn small(v: u32) -> [u32; 8] {
    [v, 0, 0, 0, 0, 0, 0, 0]
}

/// The permuted state after absorbing `(7, 11)` into a zero state, as
/// `transcript::Transcript::duplex` forms the lanes: `(7, 11, 0 + 2)`.
const AFTER_N2: [u32; 8] = [
    0xc3064652, 0x85f2cf4f, 0x1e7fe568, 0xee599b44, 0x2a1ae0a6, 0xaad60717, 0xf886e6a0, 0x19f806f6,
];
/// Lane 2 of the same state: the capacity the next step counts into.
const AFTER_N2_CAPACITY: [u32; 8] = [
    0x3b477560, 0xfe5c14ff, 0xf07ee71e, 0xb621d149, 0x8e1b2c8f, 0x4b858b31, 0x4f9ef979, 0x302d6605,
];
/// Lane 1 after then absorbing `13` alone: `(13, 0, capacity + 1)`.
const AFTER_N1_LANE1: [u32; 8] = [
    0x7bbfdea6, 0xf96f83b5, 0xa332a39c, 0x4714f67d, 0xd2cafd33, 0xa498d3ed, 0x7e547336, 0x0bcf78a2,
];
/// Lane 0 after then a pure squeeze, `n = 0`.
const AFTER_N0: [u32; 8] = [
    0xa17e07fe, 0x23099692, 0x951b55dd, 0xf2ca8691, 0xbea7285f, 0x9d8e3eff, 0x85ce9042, 0x2989ae33,
];
/// `150⁻¹`.
const INV_150: [u32; 8] = [
    0xac7ae148, 0x8b07a766, 0xcd64c567, 0xef956261, 0x4ab62e75, 0x979e45a1, 0x9be4e1f8, 0x0f29ab5a,
];
/// `2^256 − 1` reduced: an import is mod p.
const ALL_ONES_REDUCED: [u32; 8] = [
    0x4ffffffa, 0xac96341c, 0x9f60cd29, 0x36fc7695, 0x7879462e, 0x666ea36f, 0x9a07df2f, 0x0e0a77c1,
];
/// `(7 − (2^128 + 5)) mod q`: a subtraction that wraps.
const SUB_WRAPS: [u64; 4] = [
    0x3c20_8c16_d87c_fd49,
    0x9781_6a91_6871_ca8d,
    0xb850_45b6_8181_585c,
    0x3064_4e72_e131_a029,
];

/// The scalar field's modulus, which imports as 0.
const P: [u32; 8] = [
    0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72,
];

fn main() -> ! {
    let mut passed = 0u32;
    let mut check = |ok: bool| {
        if !ok {
            exit(200 + passed as i32);
        }
        passed += 1;
    };

    // FR_OP, cells 1.. (cell 0 is never written, so it stays 0).
    fr(op::IMM, 1, 0, 7);
    fr(op::IMM, 2, 0, 11);
    fr(op::MUL, 3, 1, 2);
    check(export(3) == small(77));
    fr(op::ADD, 4, 3, 1);
    check(export(4) == small(84));
    fr(op::SUB, 5, 4, 2);
    check(export(5) == small(73));
    fr(op::MAC, 5, 1, 2);
    check(export(5) == small(150));
    fr(op::INV, 6, 5, 0);
    check(export(6) == INV_150);
    fr(op::MUL, 7, 6, 5);
    fr(op::IMM, 8, 0, 1);
    fr(op::EQ, 0, 7, 8);
    fr(op::INV, 9, 0, 0);
    check(export(9) == small(0));
    fr(op::SHL, 10, 8, 5);
    check(export(10) == [5, 1, 0, 0, 0, 0, 0, 0]);
    // A destination that is both operands: 7·7 in place.
    fr(op::MUL, 1, 1, 1);
    check(export(1) == small(49));
    fr(op::EQ, 0, 1, 1);
    // DIGIT: 0x12345678 peeled a byte at a time, its rest in place, and the
    // chain ending at 0 after four digits.
    fr(op::IMM, 11, 0, 0x1234_5678);
    fr(op::DIGIT, 12, 11, 11);
    check(export(12) == small(0x78));
    check(export(11) == small(0x12_3456));
    fr(op::DIGIT, 13, 11, 11);
    fr(op::DIGIT, 14, 11, 11);
    fr(op::DIGIT, 15, 11, 11);
    check(export(15) == small(0x12));
    fr(op::EQ, 0, 11, 0);

    // FIELD_IO: a word vector round trip, and two reductions.
    let words: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    import(20, &words);
    check(export(20) == words);
    import(21, &P);
    check(export(21) == small(0));
    import(22, &[u32::MAX; 8]);
    check(export(22) == ALL_ONES_REDUCED);

    // P2_FIELD, states at 100, 103, 106, 109; values at 30, 31, 32. Each step
    // names where its state goes.
    fr(op::IMM, 30, 0, 7);
    fr(op::IMM, 31, 0, 11);
    fr(op::IMM, 32, 0, 13);
    p2_field(&mut [2, 100, 30, 31, 103]);
    check(export(103) == AFTER_N2);
    check(export(105) == AFTER_N2_CAPACITY);
    p2_field(&mut [1, 103, 32, 0, 106]);
    check(export(107) == AFTER_N1_LANE1);
    p2_field(&mut [0, 106, 0, 0, 109]);
    check(export(109) == AFTER_N0);

    // FQ_OP: x = 2^128 + 5 and y = 7 from their limb cells, then each op.
    fr(op::IMM, 200, 0, 5);
    fr(op::IMM, 201, 0, 1);
    fr(op::IMM, 204, 0, 7);
    fqe(fq::FROM128, 210, 200, ZERO_ELEMENT);
    fqe(fq::FROM128, 214, 204, ZERO_ELEMENT);
    fqe(fq::MUL, 218, 210, 214);
    // An element is read whole until it is dead: an export reads its cells
    // one at a time, so the assertion comes before it.
    fqe(fq::MULEQ, 218, 210, 214);
    check(element(218) == [35, 0, 7, 0]);
    fqe(fq::ADD, 222, 210, 214);
    check(element(222) == [12, 0, 1, 0]);
    fqe(fq::SUB, 226, 214, 210);
    check(element(226) == SUB_WRAPS);
    // q − 1, squared, reduces to 1.
    wide(230, [0x9781_6a91, 0x6871_ca8d, 0x3c20_8c16, 0xd87c_fd46]);
    wide(231, [0x3064_4e72, 0xe131_a029, 0xb850_45b6, 0x8181_585d]);
    fqe(fq::FROM128, 234, 230, ZERO_ELEMENT);
    fqe(fq::MUL, 238, 234, 234);
    check(element(238) == [1, 0, 0, 0]);
    // Indirect: digit 2 at cell 240, so bucket 2 of the buckets at 300.
    fr(op::IMM, 240, 0, 2);
    let digit = 240 << fq::DIGIT_SHIFT;
    fqe(fq::FROM128, 316, 204, ZERO_ELEMENT);
    fqe(fq::ADD | fq::IND_A | digit, 250, 300, 214);
    check(element(250) == [14, 0, 0, 0]);
    fqe(fq::MUL | fq::IND_D | digit, 304, 210, 214);
    check(element(320) == [35, 0, 7, 0]);

    exit(passed as i32 - 1)
}
