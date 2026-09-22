//! S22's step program, **interpreted**.
//!
//! `constraints::ecrecover::schedule` is the straight-line program one
//! `ECRECOVER` invocation runs, a row a step. This suite runs it over
//! `program::secp256k1` — the same arithmetic the emulator executes and the
//! witness builder will fill from — and holds its answer to what `recover`
//! returns, over the committed corpus.
//!
//! That is the one check that says the **program is the right program**, and
//! it is worth making before a single gate exists: a gate list built from a
//! wrong program is a correct circuit for the wrong function, and every later
//! test would agree with it.
//!
//! The interpreter is also the specification of each step's semantics. The
//! circuit's gates and `trace`'s witness builder both have to agree with it,
//! and where they do not, this file is what says which is wrong.

use std::collections::BTreeMap;

use constants::ecrecover as e;
use constants::secp256k1 as k;
use constraints::ecrecover::schedule::{Digit, Frame, Modulus, Output, Schedule, Step};
use constraints::ecrecover::{schedule, SELECTORS, TABLE, WINDOWS, WINDOW_BITS};
use program::secp256k1 as s2;
use s2::U256;

// ---------------------------------------------------------------------------
// The witness a prover chooses
// ---------------------------------------------------------------------------

/// A 320-bit integer, which is all the digit recoding needs: `u + n` is
/// under `2^257` and the recoding only shrinks it.
type Wide = [u64; 5];

fn widen(v: &U256) -> Wide {
    [v[0], v[1], v[2], v[3], 0]
}

fn wide_add(a: &Wide, b: &Wide) -> Wide {
    let mut out = [0u64; 5];
    let mut carry = 0u128;
    for (i, o) in out.iter_mut().enumerate() {
        let wide = a[i] as u128 + b[i] as u128 + carry;
        *o = wide as u64;
        carry = wide >> 64;
    }
    assert_eq!(carry, 0, "the recoding stays under 2^320");
    out
}

/// `(a − d) >> bits`, for a small signed `d` that `a − d` is a multiple of.
fn wide_shift_off(a: &Wide, d: i64, bits: u32) -> Wide {
    // Subtract `d`, which may be negative.
    let mut out = *a;
    if d >= 0 {
        let mut borrow = d as u128;
        for o in out.iter_mut() {
            let wide = (*o as u128).wrapping_sub(borrow);
            *o = wide as u64;
            borrow = u128::from(wide >> 127 != 0);
        }
        assert_eq!(borrow, 0, "the recoding never goes negative");
    } else {
        out = wide_add(&out, &[d.unsigned_abs(), 0, 0, 0, 0]);
    }
    let mut shifted = [0u64; 5];
    for i in 0..5 {
        shifted[i] = out[i] >> bits;
        if i + 1 < 5 {
            shifted[i] |= out[i + 1] << (64 - bits);
        }
    }
    shifted
}

fn wide_is_small(a: &Wide) -> bool {
    a[1..].iter().all(|w| *w == 0)
}

/// The digits of one scalar, most significant first.
///
/// Signed and **odd**: every digit is one of `±1, ±3, … ±(2^w − 1)`, so no
/// window ever adds the identity and the chord formula's degenerate case
/// never arises from a zero digit. A scalar is made odd first — `u` and
/// `u + n` are the same multiple of a point of order `n`, and exactly one of
/// them is odd — and the recoding keeps it odd at every step after.
fn signed_odd_digits(u: &U256) -> Vec<i64> {
    let mut value = widen(u);
    if value[0] & 1 == 0 {
        value = wide_add(&value, &widen(&k::N));
    }
    assert!(value[0] & 1 == 1, "one of u and u + n is odd");

    let radix = 1i64 << WINDOW_BITS;
    let mask = (1u64 << (WINDOW_BITS + 1)) - 1;
    let mut digits = Vec::with_capacity(WINDOWS);
    for _ in 0..WINDOWS - 1 {
        let d = (value[0] & mask) as i64 - radix;
        digits.push(d);
        value = wide_shift_off(&value, d, WINDOW_BITS);
    }
    assert!(wide_is_small(&value), "the recoding ran out of windows");
    let last = value[0] as i64;
    assert!(
        last > 0 && last < radix && last % 2 != 0,
        "the last digit {last} is not an odd digit of the table"
    );
    digits.push(last);
    digits.reverse();
    digits
}

/// Which selector a signed digit lights: the positive magnitudes first, then
/// the negative ones, as `constraints::ecrecover::odd_multiples` lays the
/// tables out.
fn selector_of(d: i64) -> usize {
    let magnitude = d.unsigned_abs() as usize;
    assert!(
        magnitude % 2 == 1 && magnitude < 1 << WINDOW_BITS,
        "digit {d}"
    );
    let index = (magnitude - 1) / 2;
    if d > 0 {
        index
    } else {
        TABLE + index
    }
}

// ---------------------------------------------------------------------------
// The machine
// ---------------------------------------------------------------------------

struct Machine {
    bus: BTreeMap<u32, U256>,
    frame: Vec<u32>,
    digits: BTreeMap<&'static str, std::collections::VecDeque<i64>>,
    /// Whether `x³ + 7` is a square, which the program witnesses as a free
    /// boolean and its two roots then force.
    is_residue: bool,
    /// The parity the recovered `y` must have, which is `v`'s.
    root_parity: u64,
    /// The step being run, so a failure says where in the program it was.
    at: usize,
}

fn modulus(m: Modulus) -> U256 {
    match m {
        Modulus::Field => k::P,
        Modulus::Order => k::N,
    }
}

/// `c·v` for a small signed `c`, modulo `m`.
fn scale(c: i64, v: &U256, m: &U256) -> U256 {
    let magnitude = s2::mulmod(&[c.unsigned_abs(), 0, 0, 0], v, m);
    if c < 0 {
        s2::submod(&s2::ZERO, &magnitude, m)
    } else {
        magnitude
    }
}

impl Machine {
    fn read(&self, at: u32, note: &str) -> U256 {
        *self
            .bus
            .get(&at)
            .unwrap_or_else(|| panic!("`{note}` read bus address {at}, which nothing wrote"))
    }

    fn write(&mut self, step: &Step, value: U256) {
        if !step.bused {
            return;
        }
        // `APOGEE_TRACE_SCHEDULE=1` prints every value the program computes.
        // The witness builder has to reproduce exactly this list, and a diff
        // against it is how a disagreement gets found.
        if std::env::var("APOGEE_TRACE_SCHEDULE").is_ok() {
            println!(
                "{:>5} {:<24} {:016x}{:016x}{:016x}{:016x}",
                self.at, step.note, value[3], value[2], value[1], value[0]
            );
        }
        for at in &step.writes {
            let previous = self.bus.insert(*at, value);
            assert!(
                previous.is_none(),
                "`{}` wrote bus address {at} twice",
                step.note
            );
        }
    }

    /// The frame words a read step assembles, as one value.
    fn frame_value(&self, words: &[u32; 8]) -> U256 {
        let mut out = s2::ZERO;
        for (i, w) in words.iter().enumerate() {
            if *w == u32::MAX {
                continue;
            }
            out[i / 2] |= (self.frame[*w as usize] as u64) << (32 * (i % 2));
        }
        out
    }

    /// Every term of the congruence but the output slot, modulo `m`.
    fn rest(&mut self, step: &Step, m: &U256) -> U256 {
        let mut sum = s2::rem(&step.literal, m);
        if let (Some(a), Some(b)) = (step.a, step.b) {
            if matches!(step.output, Output::None | Output::D) {
                let x = self.read(a, step.note);
                let y = self.read(b, step.note);
                sum = s2::addmod(&sum, &s2::mulmod(&x, &y, m), m);
            }
        }
        for (coefficient, at) in [step.c, step.e, step.d].into_iter().flatten() {
            let v = self.read(at, step.note);
            sum = s2::addmod(&sum, &scale(coefficient, &v, m), m);
        }
        if let Some(index) = self.selector(step) {
            let entry = if step.table.is_empty() {
                s2::rem(&step.table_literals[index], m)
            } else {
                self.read(step.table[index], step.note)
            };
            sum = s2::addmod(&sum, &entry, m);
        }
        sum
    }

    /// Which selector this row lights, if it has any.
    fn selector(&mut self, step: &Step) -> Option<usize> {
        match step.digit {
            Digit::None => None,
            Digit::Emit => {
                let queue = self
                    .digits
                    .get_mut(step.note)
                    .unwrap_or_else(|| panic!("no digits for `{}`", step.note));
                let d = queue.pop_front().expect("a digit for every window");
                Some(selector_of(d))
            }
            Digit::Check(at) => {
                let shifted = self.read(at, step.note);
                assert!(
                    shifted[1..].iter().all(|w| *w == 0),
                    "`{}`: a shifted digit is one limb",
                    step.note
                );
                Some(selector_of(shifted[0] as i64 - (1 << WINDOW_BITS)))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// One step
// ---------------------------------------------------------------------------

impl Machine {
    fn step(&mut self, step: &Step) {
        // The exact steps are integer statements, not modular ones, and the
        // two shapes the program uses are handled on their own terms:
        // `docs/spec/ecrecover.md` §3.2's lift is what makes them different.
        match step.frame {
            Frame::Read(words) => {
                let value = self.frame_value(&words);
                self.write(step, value);
                return;
            }
            Frame::Write(words) => {
                let (_, at) = step.c.expect("a frame write reads its value");
                let value = self.read(at, step.note);
                for (i, w) in words.iter().enumerate() {
                    if *w == u32::MAX {
                        continue;
                    }
                    self.frame[*w as usize] = (value[i / 2] >> (32 * (i % 2))) as u32;
                }
                return;
            }
            Frame::None => {}
        }
        if step.is_zero {
            // `z = [x = 0]`, on the value in the product's left slot. The
            // circuit tests two 128-bit halves and multiplies the results,
            // because a 256-bit value recomposed to one `Fr` is 6-to-1
            // (`docs/spec/ecrecover.md` §3.4); the interpreter works over
            // integers, where the whole value is the test.
            let at = step.a.expect("an is-zero step names what it tests");
            let value = self.read(at, step.note);
            let z = if s2::is_zero(&value) {
                s2::ONE
            } else {
                s2::ZERO
            };
            self.write(step, z);
            return;
        }
        if step.exact {
            // `coefficient·out + Σ terms = 0` over ℤ. The program's one use is
            // the parity split, whose coefficient is 2.
            let coefficient = step.out_coeff;
            let mut sum = 0i128;
            let mut wide = s2::ZERO;
            let mut negative = s2::ZERO;
            for (c, at) in [step.c, step.e].into_iter().flatten() {
                let v = self.read(at, step.note);
                if c > 0 {
                    for _ in 0..c {
                        wide = s2::add(&wide, &v).0;
                    }
                } else {
                    for _ in 0..-c {
                        negative = s2::add(&negative, &v).0;
                    }
                }
                sum += c as i128;
            }
            let _ = sum;
            // out = (negative − wide) / coefficient, exactly.
            let (difference, borrow) = s2::sub(&negative, &wide);
            assert!(!borrow, "`{}`: an exact step went negative", step.note);
            assert!(coefficient > 0, "`{}`: an exact step divides", step.note);
            let (quotient, remainder) = divide_small(&difference, coefficient as u64);
            assert_eq!(
                remainder, 0,
                "`{}`: the exact step does not divide, so the parity is wrong",
                step.note
            );
            self.write(step, quotient);
            return;
        }

        let m = modulus(step.modulus);
        match step.output {
            Output::None => {
                let rest = self.rest(step, &m);
                assert!(
                    s2::is_zero(&rest),
                    "`{}`: the assertion does not hold; the slack is {:?}",
                    step.note,
                    rest
                );
            }
            Output::D => {
                let rest = self.rest(step, &m);
                let coefficient = step.out_coeff;
                let value = if coefficient == -1 {
                    rest
                } else {
                    let scaled = scale(-coefficient, &s2::ONE, &m);
                    let inverse = s2::invmod(&scaled, &m).expect("a coefficient is invertible");
                    s2::mulmod(&rest, &inverse, &m)
                };
                self.write(step, value);
            }
            Output::A => {
                // `A·B + rest ≡ 0`, so `A = −rest/B`.
                let rest = self.rest(step, &m);
                let b = self.read(step.b.expect("a division names its divisor"), step.note);
                let inverse = s2::invmod(&b, &m).unwrap_or_else(|| {
                    panic!(
                        "`{}` at step {}: the divisor is zero, which the circuit refuses",
                        step.note, self.at
                    )
                });
                let negated = s2::submod(&s2::ZERO, &rest, &m);
                self.write(step, s2::mulmod(&negated, &inverse, &m));
            }
            Output::Sqrt => {
                let rest = self.rest(step, &m);
                let value = if step.a_coeff == -1 {
                    // `A² − A ≡ 0`: a free boolean, and the note says which.
                    assert!(s2::is_zero(&rest), "a free boolean carries no other term");
                    self.free_boolean(step.note)
                } else {
                    let target = s2::submod(&s2::ZERO, &rest, &m);
                    self.root(step.note, &target, &m)
                };
                self.write(step, value);
            }
        }
    }

    /// The boolean a `sqrt`-shaped booleanity step witnesses.
    fn free_boolean(&mut self, note: &'static str) -> U256 {
        match note {
            "is_residue" => [u64::from(self.is_residue), 0, 0, 0],
            other => panic!("no witness for the free boolean `{other}`"),
        }
    }

    /// A square root of `target` modulo `m`, with the parity the program's
    /// later parity split will demand.
    ///
    /// `p ≡ 3 mod 4`, so `target^((p+1)/4)` is a root when one exists; a
    /// prover picks between it and its negation, and the exact split of
    /// `docs/spec/ecrecover.md` §4.2 is what makes that choice forced.
    fn root(&mut self, note: &'static str, target: &U256, m: &U256) -> U256 {
        if s2::is_zero(target) {
            return s2::ZERO;
        }
        let candidate = s2::powmod(target, &k::P_PLUS_1_OVER_4, m);
        assert_eq!(
            s2::mulmod(&candidate, &candidate, m),
            *target,
            "`{note}`: no square root exists, so the witness the program asks for is absent"
        );
        let other = s2::submod(&s2::ZERO, &candidate, m);
        if note == "curve_y" && candidate[0] & 1 != self.root_parity & 1 {
            other
        } else {
            candidate
        }
    }
}

/// `v / d` and `v mod d`, for a small `d`. `div_rem_wide` wants a normalized
/// divisor and this one is 2.
fn divide_small(v: &U256, d: u64) -> (U256, u64) {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for i in (0..4).rev() {
        let wide = (carry << 64) | v[i] as u128;
        out[i] = (wide / d as u128) as u64;
        carry = wide % d as u128;
    }
    (out, carry as u64)
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/// Every choice the program leaves to the prover, worked out natively.
///
/// A schedule says what is computed, not what is witnessed. These four are
/// the whole of what a prover picks: whether the curve's right-hand side is a
/// square, which root of it to take, and the two digit strings. Everything
/// else each step determines.
struct Witness {
    is_residue: bool,
    root_parity: u64,
    u1: Vec<i64>,
    u2: Vec<i64>,
}

fn witness(hash: &U256, v: u32, r: &U256, s: &U256) -> Witness {
    let r_n = s2::rem(r, &k::N);
    let s_n = s2::rem(s, &k::N);
    let r_ok = r_n == *r && !s2::is_zero(&r_n);
    let s_ok = s_n == *s && !s2::is_zero(&s_n);
    let v_ok = (e::V_MIN..=e::V_MAX).contains(&v);
    let inputs_ok = r_ok && s_ok && v_ok;

    let x = s2::rem(&r_n, &k::P);
    let rhs = s2::addmod(
        &s2::mulmod(&s2::mulmod(&x, &x, &k::P), &x, &k::P),
        &[7, 0, 0, 0],
        &k::P,
    );
    let root = s2::powmod(&rhs, &k::P_PLUS_1_OVER_4, &k::P);
    let is_residue = s2::mulmod(&root, &root, &k::P) == rhs;

    let ok = inputs_ok && is_residue;
    let par = v.saturating_sub(e::V_MIN);
    let root_parity = u64::from(ok) * u64::from(par);

    let r_used = if ok { r_n } else { s2::ONE };
    let r_inv = s2::invmod(&r_used, &k::N).expect("a nonzero scalar inverts");
    let hash_n = s2::rem(hash, &k::N);
    let u1 = s2::submod(&s2::ZERO, &s2::mulmod(&hash_n, &r_inv, &k::N), &k::N);
    let u2 = s2::mulmod(&s_n, &r_inv, &k::N);
    Witness {
        is_residue,
        root_parity,
        u1: signed_odd_digits(&u1),
        u2: signed_odd_digits(&u2),
    }
}

/// Run one invocation of the program over a frame, and give back the frame it
/// leaves.
fn run(program: &Schedule, frame: &[u32]) -> Vec<u32> {
    let hash = s2::from_frame_words(&frame[e::OFF_HASH..e::OFF_V]);
    let r = s2::from_frame_words(&frame[e::OFF_R..e::OFF_S]);
    let s = s2::from_frame_words(&frame[e::OFF_S..e::OFF_PUBKEY_X]);
    let w = witness(&hash, frame[e::OFF_V], &r, &s);

    let mut digits = BTreeMap::new();
    digits.insert("window_g_digit", w.u1.into_iter().collect());
    digits.insert("window_r_digit", w.u2.into_iter().collect());
    let mut machine = Machine {
        bus: BTreeMap::new(),
        frame: frame.to_vec(),
        digits,
        is_residue: w.is_residue,
        root_parity: w.root_parity,
        at: 0,
    };
    for (at, step) in program.steps.iter().enumerate() {
        machine.at = at;
        machine.step(step);
    }
    machine.frame
}

/// One line of the committed corpus.
struct Case {
    name: String,
    hash: U256,
    v: u32,
    r: U256,
    s: U256,
}

fn corpus() -> Vec<Case> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/ecrecover.txt");
    let text = std::fs::read_to_string(&path).expect("the corpus");
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let value = |s: &str| s2::from_be_bytes(&test_support::hex_to_32(s).expect("32 bytes"));
        out.push(Case {
            name: f[0].to_string(),
            hash: value(f[2]),
            v: f[1].parse().expect("v"),
            r: value(f[3]),
            s: value(f[4]),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// The program computes `ecrecover`: over the whole committed corpus, the
/// frame the schedule leaves is the frame `apply_frame` leaves, which is what
/// the emulator executes and what an outside oracle answered.
///
/// This is the check that says the schedule is the right program.
#[test]
fn the_step_program_recovers_what_the_native_recovery_does() {
    let program = schedule();
    let mut succeeded = 0;
    let mut failed = 0;
    for case in corpus() {
        let frame = s2::frame_of(&case.hash, case.v, &case.r, &case.s);
        let mut want = frame.to_vec();
        s2::apply_frame(&mut want);
        let got = run(&program, &frame);
        assert_eq!(
            got, want,
            "{}: the step program and the native recovery disagree",
            case.name
        );
        if want[e::OFF_SUCCESS] == 1 {
            succeeded += 1;
        } else {
            failed += 1;
        }
    }
    assert!(
        succeeded >= 10 && failed >= 6,
        "the corpus exercises both outcomes: {succeeded} succeeded, {failed} failed"
    );
}

/// The digit recoding is a representation of the scalar, and every digit is
/// one the table holds — which is what keeps a zero digit, and with it the
/// identity addition, out of the ladder entirely.
#[test]
fn every_digit_is_odd_signed_and_in_the_table() {
    let mut rng = test_support::Rng::new(0x5ec2_6b1d);
    for _ in 0..64 {
        let mut limbs = [0u64; 4];
        for limb in limbs.iter_mut() {
            *limb = rng.next_u64();
        }
        let u = s2::rem(&limbs, &k::N);
        let digits = signed_odd_digits(&u);
        assert_eq!(digits.len(), WINDOWS);
        for d in &digits {
            assert!(d % 2 != 0, "a digit is odd");
            assert!(
                d.unsigned_abs() < 1 << WINDOW_BITS,
                "a digit is in the table"
            );
            assert!(selector_of(*d) < SELECTORS);
        }
        // The digits are the scalar, modulo the group order: Horner from the
        // most significant.
        let mut value = s2::ZERO;
        for d in &digits {
            for _ in 0..WINDOW_BITS {
                value = s2::addmod(&value, &value, &k::N);
            }
            let magnitude = [d.unsigned_abs(), 0, 0, 0];
            value = if *d > 0 {
                s2::addmod(&value, &magnitude, &k::N)
            } else {
                s2::submod(&value, &magnitude, &k::N)
            };
        }
        assert_eq!(value, u, "the digits do not recompose to the scalar");
    }
}

/// The program fits its block, and the block is the constant the rest of the
/// repository reads.
#[test]
fn the_program_fits_the_invocation_block() {
    let program = schedule();
    assert!(
        program.steps.len() <= e::ROWS_PER_INVOCATION,
        "the program is {} steps and the block is {} rows",
        program.steps.len(),
        e::ROWS_PER_INVOCATION
    );
    assert!(
        program.steps.len() * 2 > e::ROWS_PER_INVOCATION,
        "the block is more than twice the program: a smaller one would do"
    );
    assert_eq!(
        program.fan_out,
        constraints::ecrecover::FAN_OUT,
        "the program's widest write is the cap the row provisions"
    );
}
