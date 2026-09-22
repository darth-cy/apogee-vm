//! The `ECRECOVER` delegation family.
//!
//! [`schedule`] is the straight-line program one invocation runs, a row a
//! step, and `docs/spec/ecrecover.md` is what it implements. The circuit is
//! that program's row shape; the witness builder fills it; and
//! `crates/program/tests/ecrecover_schedule.rs` interprets it over
//! `program::secp256k1` and checks it recovers what the native `recover`
//! does — which is how the program is known to be right before a gate exists.

pub mod schedule;

use alloc::vec::Vec;

use constants::ecrecover as e;
use constants::secp256k1 as k;

use schedule::{Builder, Modulus::Field, Modulus::Order, Schedule, Val};

// ---------------------------------------------------------------------------
// The parameters the row budget turns on
// ---------------------------------------------------------------------------

/// The most bus addresses one step writes, and so the most readers one value
/// may have before the program owes it copy steps.
///
/// Every row pays for these write leaves whether it uses them or not, and a
/// value read more often than this costs a copy step — so the cap trades the
/// width of every row against the length of the program.
pub const FAN_OUT: usize = 6;

/// Bits a scalar window. The digits are **signed and odd**, `±1, ±3, … ±(2^w − 1)`,
/// which is what keeps a zero digit — an identity addition, and the
/// degenerate case of `docs/spec/ecrecover.md` §5.3 — out of the ladder
/// entirely.
pub const WINDOW_BITS: u32 = 3;

/// Windows a scalar: `⌈256 / WINDOW_BITS⌉`.
pub const WINDOWS: usize = 86;

/// Odd multiples a table holds: `1, 3, … 2^w − 1`.
pub const TABLE: usize = 1 << (WINDOW_BITS - 1);

/// Selectors a window's one-hot columns carry: one per **signed** digit,
/// `±1, ±3, … ±(2^w − 1)`.
///
/// The sign lives in the selector rather than in a column of its own. A
/// column would have to be tied to the digit on every row that reads it and
/// then multiplied into the selection, which is degree three; folding it into
/// the one-hot set costs four more bused table entries and nothing else.
pub const SELECTORS: usize = 2 * TABLE;

const _: () = assert!(WINDOWS as u32 * WINDOW_BITS >= 256);

// ---------------------------------------------------------------------------
// Small integer helpers, on limbs
// ---------------------------------------------------------------------------

const ZERO: [u64; 4] = [0; 4];
const ONE: [u64; 4] = [1, 0, 0, 0];

/// `m − c` for a small `c`, as limbs: how a step adds a negative constant.
/// Every modulus here is far above any `c` a step uses.
const fn less(m: [u64; 4], c: u64) -> [u64; 4] {
    assert!(
        m[0] >= c,
        "the low limb absorbs every constant this program uses"
    );
    [m[0] - c, m[1], m[2], m[3]]
}

/// A value's eight frame words, low word first.
fn words(offset: usize) -> [u32; 8] {
    let mut out = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = (offset + i) as u32;
        i += 1;
    }
    out
}

/// One frame word as a value; the rest of the slots contribute nothing.
fn word(offset: usize) -> [u32; 8] {
    let mut out = [u32::MAX; 8];
    out[0] = offset as u32;
    out
}

// ---------------------------------------------------------------------------
// Points
// ---------------------------------------------------------------------------

/// An affine point on the bus. There is no infinity flag: the digits are
/// signed and odd, so no addition in this program adds the identity, and the
/// accumulator is initialized from a table entry rather than from `O`.
#[derive(Clone, Copy, Debug)]
struct Point {
    x: Val,
    y: Val,
}

/// A point fanned out to exactly the reads an operation takes.
///
/// Every read is spelled out because a multiset bus makes fan-out a cost
/// rather than a convenience: a value read more often than its producer
/// writes copies has no witness at all. Declaring the counts is also what
/// keeps a caller from handing one use to an operation that takes three.
struct Reads {
    x: Vec<Val>,
    y: Vec<Val>,
}

/// Reads [`double`] takes of each coordinate.
const DOUBLE_READS: (usize, usize) = (4, 3);
/// Reads [`add`] takes of the accumulator's coordinates, and of the addend's.
const ADD_LEFT: (usize, usize) = (3, 2);
const ADD_RIGHT: (usize, usize) = (2, 1);

fn reads(b: &mut Builder, note: &'static str, p: Point, want: (usize, usize)) -> Reads {
    Reads {
        x: b.fanout(note, Field, p.x, want.0),
        y: b.fanout(note, Field, p.y, want.1),
    }
}

/// `1 − v`, for a boolean `v`.
fn not(b: &mut Builder, note: &'static str, v: Val) -> Val {
    b.lin(note, Field, &[(-1, v)], ONE)
}

/// `2·(x, y)`, by the tangent.
///
/// The witnessed slope is `lam = 2λ = 3x²/y`, which spares the step that
/// would otherwise form `2y`; the two gates below carry the factor back.
/// `y ≠ 0` is **asserted** rather than argued: it is what keeps `lam`
/// determined, and a free slope anywhere in the ladder recovers an arbitrary
/// public key from an honest signature (`docs/spec/ecrecover.md` §5.3).
fn double(b: &mut Builder, p: &Reads) -> Point {
    b.assert_invertible("dbl_y_nonzero", Field, p.y[0]);
    let xsq = b.mul("dbl_x_squared", Field, p.x[0], p.x[1]);
    let lam = b.div("dbl_slope", Field, p.y[1], &[(-3, xsq)], ZERO);
    let lam = b.fanout("dbl_slope_copies", Field, lam, 3);
    let x3 = b.mul_add_scaled("dbl_x3", Field, (lam[0], lam[1]), &[(-8, p.x[2])], ZERO, -4);
    let x3 = b.fanout("dbl_x3_copies", Field, x3, 2);
    let w = b.lin("dbl_gap", Field, &[(1, p.x[3]), (-1, x3[0])], ZERO);
    let y3 = b.mul_add_scaled("dbl_y3", Field, (lam[2], w), &[(-2, p.y[2])], ZERO, -2);
    Point { x: x3[1], y: y3 }
}

/// `p + q`, by the chord.
///
/// `p.x ≠ q.x` is asserted by the inverse the slope is built from, which is
/// the same rule as the doubling's and is why the digits are never zero.
fn add(b: &mut Builder, p: &Reads, q: &Reads) -> Point {
    let dx = b.lin("add_dx", Field, &[(1, q.x[0]), (-1, p.x[0])], ZERO);
    let dxinv = b.div("add_dx_nonzero", Field, dx, &[], less(k::P, 1));
    let dy = b.lin("add_dy", Field, &[(1, q.y[0]), (-1, p.y[0])], ZERO);
    let lam = b.mul("add_slope", Field, dy, dxinv);
    let lam = b.fanout("add_slope_copies", Field, lam, 3);
    let x3 = b.mul_add(
        "add_x3",
        Field,
        lam[0],
        lam[1],
        &[(-1, p.x[1]), (-1, q.x[1])],
        ZERO,
    );
    let x3 = b.fanout("add_x3_copies", Field, x3, 2);
    let w = b.lin("add_gap", Field, &[(1, p.x[2]), (-1, x3[0])], ZERO);
    let y3 = b.mul_add("add_y3", Field, lam[2], w, &[(-1, p.y[1])], ZERO);
    Point { x: x3[1], y: y3 }
}

// ---------------------------------------------------------------------------
// The program
// ---------------------------------------------------------------------------

/// The step program one invocation runs.
pub fn schedule() -> Schedule {
    let mut b = Builder::new(FAN_OUT);

    // ---- the frame ----------------------------------------------------
    // A frame value is eight words and is **not** canonical: the guest hands
    // over 32 arbitrary bytes, and a value at or above the modulus has to be
    // a provable failure rather than an unprovable execution
    // (`docs/spec/ecrecover.md` §1.3). A non-canonical value may be a linear
    // operand and nothing else, which is all the four below ever are.
    let hash = b.frame_read("frame_hash", words(e::OFF_HASH));
    let v_raw = b.frame_read("frame_v", word(e::OFF_V));
    let r_raw = b.frame_read("frame_r", words(e::OFF_R));
    let s_raw = b.frame_read("frame_s", words(e::OFF_S));

    // ---- validity -----------------------------------------------------
    let r_ok = in_range(&mut b, "r", r_raw);
    let s_ok = in_range(&mut b, "s", s_raw);
    // `v ∈ {27, 28}`: `par = v − 27` is boolean exactly then, and `v` is one
    // 32-bit word, so no other `v` is congruent to 0 or 1.
    let par = b.lin(
        "v_parity",
        Field,
        &[(1, v_raw)],
        less(k::P, e::V_MIN as u64),
    );
    let par = b.fanout("v_parity_copies", Field, par, 4);
    let par_sq = b.mul_add(
        "v_parity_square",
        Field,
        par[0],
        par[1],
        &[(-1, par[2])],
        ZERO,
    );
    let v_ok = b.is_zero("v_in_range", par_sq);

    let r_n = r_ok.value;
    let s_n = s_ok.value;
    let ok_rs = b.mul("valid_r_s", Field, r_ok.ok, s_ok.ok);
    let inputs_ok = b.mul("valid_inputs", Field, ok_rs, v_ok);

    // ---- the point at x = r -------------------------------------------
    // `r < n < p`, so the same integer is canonical in both fields; the step
    // is a copy whose canonicality is now against `p`.
    let x = b.lin("point_x", Field, &[(1, r_n)], ZERO);
    let x = b.fanout("point_x_copies", Field, x, 4);
    let xsq = b.mul("point_x_squared", Field, x[0], x[1]);
    let xcu = b.mul("point_x_cubed", Field, xsq, x[2]);
    let rhs = b.lin("curve_rhs", Field, &[(1, xcu)], [7, 0, 0, 0]);
    let rhs = b.fanout("curve_rhs_copies", Field, rhs, 2);

    // Exactly one of `rhs` and `−rhs` is a square, because `p ≡ 3 mod 4`
    // makes `−1` a non-residue. So the two roots below are **both** always
    // witnessable, and which one is nontrivial forces `residue` to the truth:
    // a prover claiming a square where there is none has no `y`, and one
    // claiming none where there is one has no `w`.
    let residue = b.boolean("is_residue");
    let residue = b.fanout("is_residue_copies", Field, residue, 3);
    let live = b.mul("residue_part", Field, residue[0], rhs[0]);
    let live = b.fanout("residue_part_copies", Field, live, 2);
    let y0 = b.sqrt("curve_y", Field, &[(-1, live[0])], ZERO);
    let dead = b.lin(
        "nonresidue_part",
        Field,
        &[(1, rhs[1]), (-1, live[1])],
        ZERO,
    );
    b.sqrt("nonresidue_witness", Field, &[(1, dead)], ZERO);
    b.discard_last();

    // `ok` is every reason the call can succeed, and from here on a failing
    // call runs the same rows on substitute values: the ladder must never see
    // a point that is not on the curve, or an exceptional case could make an
    // honest prover unable to prove a **failure**.
    let ok = b.mul("recovery_ok", Field, inputs_ok, residue[1]);
    let ok = b.fanout("recovery_ok_copies", Field, ok, 7);

    // The root's parity is `v`'s, forced over ℤ: `y = 2h + par` has an
    // integer `h` only for the root of that parity, so the prover's choice of
    // root is not a choice. Modulo `p` it would hold for either.
    let y0 = b.fanout("curve_y_copies", Field, y0, 2);
    let par_used = b.mul("parity_used", Field, ok[0], par[3]);
    b.exact("y_parity_split", 2, &[(1, par_used), (-1, y0[0])], ZERO);
    b.discard_last();

    // ---- the scalars ---------------------------------------------------
    let one = b.constant("one", Order, ONE);
    let r_used = select(&mut b, "r_used", Order, ok[1], r_n, one);
    let r_inv = b.div("r_inverse", Order, r_used, &[], less(k::N, 1));
    let r_inv = b.fanout("r_inverse_copies", Order, r_inv, 2);
    let hash_n = b.lin("hash_mod_n", Order, &[(1, hash)], ZERO);
    let quot = b.mul("hash_over_r", Order, hash_n, r_inv[0]);
    let u1 = b.lin("u1", Order, &[(-1, quot)], ZERO);
    let u2 = b.mul("u2", Order, s_n, r_inv[1]);

    // ---- the point the ladder runs on ----------------------------------
    // The substitute is `H`, not `G`: see `constants::secp256k1::H_X`. With
    // both of the ladder's bases equal, its accumulator and its addend are
    // multiples of one point and the chord's exceptional case turns up within
    // a few windows — which would leave a **failing** call unprovable.
    let h_x = b.constant("h_x", Field, k::H_X);
    let h_y = b.constant("h_y", Field, k::H_Y);
    let base = Point {
        x: select(&mut b, "base_x", Field, ok[2], x[3], h_x),
        y: select(&mut b, "base_y", Field, ok[3], y0[1], h_y),
    };

    // ---- the tables ----------------------------------------------------
    // `R`'s odd multiples, built in circuit; `G`'s are schedule constants.
    let (table_x, table_y) = odd_multiples(&mut b, base);

    // ---- the joint ladder ----------------------------------------------
    let (acc, u1_acc, u2_acc) = ladder(&mut b, &table_x, &table_y);

    // The digits are only a scalar because of these two: without them a
    // prover picks any digit string and proves a multiple of their choosing
    // (`docs/spec/ecrecover.md` §5.2).
    b.assert_zero(
        "u1_is_the_digits",
        Order,
        None,
        &[(1, u1), (-1, u1_acc)],
        ZERO,
    );
    b.assert_zero(
        "u2_is_the_digits",
        Order,
        None,
        &[(1, u2), (-1, u2_acc)],
        ZERO,
    );

    // ---- the answer ----------------------------------------------------
    let zero = b.constant("zero", Field, ZERO);
    let zero = b.fanout("zero_copies", Field, zero, 3);
    let out_x = select(&mut b, "out_x", Field, ok[4], acc.x, zero[0]);
    let out_y = select(&mut b, "out_y", Field, ok[5], acc.y, zero[1]);
    let out_ok = b.lin("out_success", Field, &[(1, ok[6])], ZERO);
    b.frame_write("frame_pubkey_x", words(e::OFF_PUBKEY_X), out_x);
    b.frame_write("frame_pubkey_y", words(e::OFF_PUBKEY_Y), out_y);
    b.frame_write("frame_success", word(e::OFF_SUCCESS), out_ok);
    let _ = zero[2];

    b.finish()
}

/// A value reduced into `[0, n)`, and whether it was there already and
/// nonzero — the two halves of the EVM's `0 < r < n`.
struct InRange {
    value: Val,
    ok: Val,
}

/// `value mod n`, with the boolean `0 < value < n`.
///
/// `2n > 2^256`, so the quotient is 0 or 1 and the reduction costs one step;
/// the range test is then whether the reduction moved anything.
fn in_range(b: &mut Builder, note: &'static str, raw: Val) -> InRange {
    let reduced = b.lin(note, Order, &[(1, raw)], ZERO);
    let reduced = b.fanout(note, Order, reduced, 3);
    let moved = b.lin(note, Field, &[(1, raw), (-1, reduced[0])], ZERO);
    let unmoved = b.is_zero(note, moved);
    let is_zero = b.is_zero(note, reduced[1]);
    let nonzero = not(b, note, is_zero);
    InRange {
        value: reduced[2],
        ok: b.mul(note, Field, unmoved, nonzero),
    }
}

/// `if s { x } else { y }`, for a boolean `s`.
fn select(
    b: &mut Builder,
    note: &'static str,
    modulus: schedule::Modulus,
    s: Val,
    x: Val,
    y: Val,
) -> Val {
    let y = b.fanout(note, modulus, y, 2);
    let gap = b.lin(note, modulus, &[(1, x), (-1, y[0])], ZERO);
    b.mul_add(note, modulus, s, gap, &[(1, y[1])], ZERO)
}

/// `1·P, 3·P, … (2^WINDOW_BITS − 1)·P`, each fanned out to one use per
/// window.
///
/// Every window reads every entry — a one-hot selection reads the whole table
/// — so each entry is read `WINDOWS` times, and a multiset pairs one write
/// with one read. The copy steps that fan them out are the price of the
/// window, and they are most of what a wider one would cost.
fn odd_multiples(b: &mut Builder, p: Point) -> (Vec<Vec<Val>>, Vec<Vec<Val>>) {
    // Every use of a value is asked for in **one** fan-out call. Asking
    // twice spends the same budget twice, and the second ask finds a value
    // that is fully reserved with no read left to buy a copy with.
    //
    // An entry's `x` is read twice a window — once for `+d` and once for
    // `−d`, which share it — and its `y` once, the negated `y` being a bused
    // entry of its own.
    let entry_x = 2 * WINDOWS + ADD_LEFT.0;
    let entry_y = WINDOWS + 1 + ADD_LEFT.1;
    let base_x = b.fanout("table_base_x", Field, p.x, DOUBLE_READS.0 + entry_x);
    let base_y = b.fanout("table_base_y", Field, p.y, DOUBLE_READS.1 + entry_y);
    let twice = double(
        b,
        &Reads {
            x: base_x[..DOUBLE_READS.0].to_vec(),
            y: base_y[..DOUBLE_READS.1].to_vec(),
        },
    );
    let twice_x = b.fanout("table_twice_x", Field, twice.x, (TABLE - 1) * ADD_RIGHT.0);
    let twice_y = b.fanout("table_twice_y", Field, twice.y, (TABLE - 1) * ADD_RIGHT.1);

    let mut pos_x: Vec<Vec<Val>> = Vec::with_capacity(TABLE);
    let mut pos_y: Vec<Vec<Val>> = Vec::with_capacity(TABLE);
    let mut neg_y: Vec<Vec<Val>> = Vec::with_capacity(TABLE);
    let mut uses = Reads {
        x: base_x[DOUBLE_READS.0..].to_vec(),
        y: base_y[DOUBLE_READS.1..].to_vec(),
    };
    for i in 0..TABLE {
        pos_x.push(uses.x[..2 * WINDOWS].to_vec());
        pos_y.push(uses.y[..WINDOWS].to_vec());
        // `−(2i + 1)·P` is the same `x` with `p − y`.
        let negated = b.lin("table_negate_y", Field, &[(-1, uses.y[WINDOWS])], k::P);
        neg_y.push(b.fanout("table_negated_y", Field, negated, WINDOWS));
        if i + 1 == TABLE {
            break;
        }
        let next = add(
            b,
            &Reads {
                x: uses.x[2 * WINDOWS..].to_vec(),
                y: uses.y[WINDOWS + 1..].to_vec(),
            },
            &Reads {
                x: twice_x[i * ADD_RIGHT.0..(i + 1) * ADD_RIGHT.0].to_vec(),
                y: twice_y[i * ADD_RIGHT.1..(i + 1) * ADD_RIGHT.1].to_vec(),
            },
        );
        let last = i + 2 == TABLE;
        uses = Reads {
            x: b.fanout(
                "table_entry_x",
                Field,
                next.x,
                if last { 2 * WINDOWS } else { entry_x },
            ),
            y: b.fanout(
                "table_entry_y",
                Field,
                next.y,
                if last { WINDOWS + 1 } else { entry_y },
            ),
        };
    }
    // Signed-selector order: `+1, +3, … then −1, −3, …`.
    let xs = pos_x
        .iter()
        .map(|uses| uses[..WINDOWS].to_vec())
        .chain(pos_x.iter().map(|uses| uses[WINDOWS..].to_vec()))
        .collect();
    let ys = pos_y.into_iter().chain(neg_y).collect();
    (xs, ys)
}

/// The joint ladder, and the two digit accumulations that tie it to the
/// scalars.
///
/// One accumulator, shared doublings, and a window of each scalar between
/// them: `G`'s table is the schedule's own constants and `R`'s is on the bus.
/// The digits are signed and odd, so no window ever adds the identity and the
/// chord formula's exceptional case never arises from a zero digit.
fn ladder(b: &mut Builder, table_x: &[Vec<Val>], table_y: &[Vec<Val>]) -> (Point, Val, Val) {
    // `G`'s table in signed-selector order. The negated half is `p − y`,
    // worked out here because these are schedule constants either way.
    let g_x: Vec<[u64; 4]> = (0..SELECTORS)
        .map(|i| k::G_MULTIPLES[2 * (i % TABLE)][0])
        .collect();
    let g_y: Vec<[u64; 4]> = (0..SELECTORS)
        .map(|i| {
            let y = k::G_MULTIPLES[2 * (i % TABLE)][1];
            if i < TABLE {
                y
            } else {
                subtract(k::P, y)
            }
        })
        .collect();
    let shift = [1u64 << WINDOW_BITS, 0, 0, 0];
    // The signed digits, in selector order, as field elements of `n`.
    let digits: Vec<[u64; 4]> = (0..SELECTORS)
        .map(|i| {
            let magnitude = (2 * (i % TABLE) + 1) as u64;
            if i < TABLE {
                [magnitude, 0, 0, 0]
            } else {
                less(k::N, magnitude)
            }
        })
        .collect();

    let mut acc: Option<Point> = None;
    let mut u1_acc: Option<Val> = None;
    let mut u2_acc: Option<Val> = None;

    for w in (0..WINDOWS).rev() {
        if let Some(a) = acc {
            let mut point = a;
            for _ in 0..WINDOW_BITS {
                let r = reads(b, "ladder_double", point, DOUBLE_READS);
                point = double(b, &r);
            }
            acc = Some(point);
        }

        // `R`'s window: one digit on the bus, three rows checked against it.
        let d2 = b.emit_digit("window_r_digit", &digits, shift);
        let d2 = b.fanout("window_r_digit_copies", Order, d2, 3);
        let rx = b.select_table("window_r_x", Field, d2[0], &slice(table_x, w), &[]);
        let ry = b.select_table("window_r_y", Field, d2[1], &slice(table_y, w), &[]);
        u2_acc = Some(accumulate(b, "u2_digits", u2_acc, d2[2]));
        acc = Some(match acc {
            None => Point { x: rx, y: ry },
            Some(a) => {
                let left = reads(b, "ladder_add_r", a, ADD_LEFT);
                let right = reads(b, "ladder_add_r", Point { x: rx, y: ry }, ADD_RIGHT);
                add(b, &left, &right)
            }
        });

        // `G`'s window, from the schedule's table.
        let d1 = b.emit_digit("window_g_digit", &digits, shift);
        let d1 = b.fanout("window_g_digit_copies", Order, d1, 3);
        let gx = b.select_table("window_g_x", Field, d1[0], &[], &g_x);
        let gy = b.select_table("window_g_y", Field, d1[1], &[], &g_y);
        u1_acc = Some(accumulate(b, "u1_digits", u1_acc, d1[2]));
        let left = reads(b, "ladder_add_g", acc.expect("live"), ADD_LEFT);
        let right = reads(b, "ladder_add_g", Point { x: gx, y: gy }, ADD_RIGHT);
        acc = Some(add(b, &left, &right));
    }
    (
        acc.expect("the ladder ran"),
        u1_acc.expect("the ladder ran"),
        u2_acc.expect("the ladder ran"),
    )
}

/// `a − b` for `a > b`, as limbs.
fn subtract(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u128;
    for i in 0..4 {
        let wide = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow);
        out[i] = wide as u64;
        borrow = u128::from(wide >> 127 != 0);
    }
    assert!(borrow == 0, "a curve constant is below the modulus");
    out
}

/// One table's `w`th copy of each entry.
fn slice(table: &[Vec<Val>], w: usize) -> Vec<Val> {
    table.iter().map(|copies| copies[w]).collect()
}

/// `acc ← 2^WINDOW_BITS·acc + (shifted − 2^WINDOW_BITS)`, over the scalar
/// field. The digit arrives shifted so that its bus value is small and
/// positive; the shift comes back off here.
fn accumulate(b: &mut Builder, note: &'static str, acc: Option<Val>, shifted: Val) -> Val {
    let back = less(k::N, 1 << WINDOW_BITS);
    match acc {
        None => b.lin(note, Order, &[(1, shifted)], back),
        Some(a) => b.lin(note, Order, &[(1 << WINDOW_BITS, a), (1, shifted)], back),
    }
}
