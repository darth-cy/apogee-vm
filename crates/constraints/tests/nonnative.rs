//! S22's non-native gadgets, checked **exhaustively at reduced width**.
//!
//! The 256-bit instance cannot be exhausted, and a carry chain is exactly the
//! kind of construction whose bugs live on inputs nobody samples. So the
//! builders in `constraints::nonnative` take their width as a parameter, and
//! these tests instantiate narrow ones — four limbs of one and of two bits —
//! where every input, every quotient and every result can be tried.
//!
//! The evaluator below is deliberately a **second implementation**: forty
//! lines of `match`, not `gkr_verify::eval_gate`. A test whose oracle is the
//! code under test proves that the code agrees with itself.
//!
//! `docs/spec/ecrecover.md` §3 is what is being checked, and §3.2's claim
//! about the last position is checked by building the gadget wrong on purpose
//! (`a_seventh_carry_makes_every_congruence_vacuous`).

use constraints::nonnative::{half, half_limbs, Bound, Canonical, Congruence, Width};
use constraints::{Coeff, GateDef, PolyAddress};
use field::Fr;

// ---------------------------------------------------------------------------
// A second evaluator
// ---------------------------------------------------------------------------

/// Every column this file uses is `W[i]`; the assignment is indexed by `i`.
fn read(values: &[Fr], address: PolyAddress) -> Fr {
    match address {
        PolyAddress::Witness(i) => values[i as usize],
        other => panic!("this test writes only witness columns, not {other}"),
    }
}

fn coeff(c: Coeff) -> Fr {
    match c {
        Coeff::Literal(v) => v,
        Coeff::Challenge(s) => panic!("this test uses no challenge, and slot {s} appeared"),
    }
}

/// One gate's value under an assignment.
fn eval(gate: &GateDef, values: &[Fr]) -> Fr {
    match gate {
        GateDef::Linear { terms, constant } => {
            terms.iter().fold(coeff(*constant), |acc, (c, a)| {
                acc + coeff(*c) * read(values, *a)
            })
        }
        GateDef::Quadratic {
            constant,
            linear,
            products,
        } => {
            let mut acc = coeff(*constant);
            for (c, a) in linear {
                acc += coeff(*c) * read(values, *a);
            }
            for (c, a, b) in products {
                acc += coeff(*c) * read(values, *a) * read(values, *b);
            }
            acc
        }
        other => panic!("the non-native gadgets write no {other:?}"),
    }
}

/// Every gate of a list, satisfied.
fn all_hold(gates: &[(String, GateDef)], values: &[Fr]) -> bool {
    gates.iter().all(|(_, g)| eval(g, values) == Fr::ZERO)
}

/// The first gate that does not hold, by name.
fn first_failure(gates: &[(String, GateDef)], values: &[Fr]) -> Option<String> {
    gates
        .iter()
        .find(|(_, g)| eval(g, values) != Fr::ZERO)
        .map(|(n, _)| n.clone())
}

/// `x` as an integer, when it is a small one.
fn to_u128(x: Fr) -> Option<u128> {
    let b = x.to_bytes();
    if b[16..].iter().any(|v| *v != 0) {
        return None;
    }
    let mut low = [0u8; 16];
    low.copy_from_slice(&b[..16]);
    Some(u128::from_le_bytes(low))
}

fn fr(x: u128) -> Fr {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(&x.to_le_bytes());
    Fr::from_bytes(&b).expect("a 128-bit value is canonical")
}

// ---------------------------------------------------------------------------
// A reduced-width instance
// ---------------------------------------------------------------------------

/// A toy field and the column layout the congruence tests use.
struct Toy {
    width: Width,
    modulus: u128,
    carry_bits: u32,
}

impl Toy {
    /// Four limbs of one bit, modulus 13: every value, quotient and carry can
    /// be enumerated, so "the honest witness is the only witness" is a
    /// statement this test can make in full.
    const TINY: Toy = Toy {
        width: Width {
            limbs: 4,
            limb_bits: 1,
            chunk_bits: 1,
        },
        modulus: 13,
        carry_bits: 6,
    };

    /// Four limbs of two bits, modulus 251: the limbs carry real products and
    /// the operand space is still exhaustible.
    const SMALL: Toy = Toy {
        width: Width {
            limbs: 4,
            limb_bits: 2,
            chunk_bits: 1,
        },
        modulus: 251,
        carry_bits: 9,
    };

    fn limbs_of(&self, v: u128) -> Vec<Fr> {
        let mask = (1u128 << self.width.limb_bits) - 1;
        (0..self.width.limbs)
            .map(|i| fr((v >> (self.width.limb_bits * i as u32)) & mask))
            .collect()
    }

    /// `W[0..4]` a, `W[4..8]` b, `W[8..12]` c, `W[12..16]` d, `W[16..20]` the
    /// modulus, `W[20..24]` the quotient, `W[24..30]` the carries.
    fn congruence(&self) -> Congruence {
        let w = |base: usize| -> Vec<PolyAddress> {
            (0..self.width.limbs)
                .map(|i| PolyAddress::Witness((base + i) as u32))
                .collect()
        };
        Congruence {
            prefix: "toy".into(),
            width: self.width,
            products: vec![(1, w(0), w(4))],
            addends: vec![(1, w(8)), (-1, w(12))],
            modulus: w(16),
            offset: 1,
            quotient: w(20),
            carries: (0..self.width.carries())
                .map(|i| PolyAddress::Witness((24 + i) as u32))
                .collect(),
            carry_bits: self.carry_bits,
        }
    }

    /// The assignment for `a·b + c − d + P = Q·P`, with the carries solved in
    /// `Fr` exactly as a prover would have to solve them.
    fn assign(&self, a: u128, b: u128, c: u128, d: u128, q: u128) -> Vec<Fr> {
        let mut values = Vec::new();
        for v in [a, b, c, d, self.modulus, q] {
            values.extend(self.limbs_of(v));
        }
        // The carries are forced: `t_k = (e_k + t_{k−1}) / radix` in `Fr`, and
        // the range check is what makes a wrong witness fail, not the chain.
        let radix = self.width.radix();
        let inv = radix.inverse().expect("the radix is invertible");
        let offset = constraints::nonnative::two_pow(self.carry_bits - 1);
        let al = self.limbs_of(a);
        let bl = self.limbs_of(b);
        let cl = self.limbs_of(c);
        let dl = self.limbs_of(d);
        let pl = self.limbs_of(self.modulus);
        let ql = self.limbs_of(q);
        let n = self.width.limbs;
        let mut carry = Fr::ZERO;
        for k in 0..self.width.carries() {
            let mut e = Fr::ZERO;
            for i in 0..n {
                if k >= i && k - i < n {
                    e = e + al[i] * bl[k - i] - ql[i] * pl[k - i];
                }
            }
            if k < n {
                e = e + cl[k] - dl[k] + pl[k];
            }
            carry = (e + carry) * inv;
            values.push(carry + offset);
        }
        values
    }

    /// The canonicality gadget over the result `d`, with its complement at
    /// `W[30..34]` and its borrows at `W[34..37]`.
    fn canonical_result(&self) -> Canonical {
        let w = |base: usize| -> Vec<PolyAddress> {
            (0..self.width.limbs)
                .map(|i| PolyAddress::Witness((base + i) as u32))
                .collect()
        };
        Canonical {
            prefix: "toy_result".into(),
            width: self.width,
            value: w(12),
            complement: w(30),
            modulus: w(16),
            borrows: (0..self.width.limbs - 1)
                .map(|i| PolyAddress::Witness((34 + i) as u32))
                .collect(),
        }
    }

    /// [`Toy::assign`], plus the result's honest complement and borrows.
    /// Panics where `d` is not below the modulus: there is no such witness,
    /// which is what `canonicality_admits_exactly_the_values_below_the_modulus`
    /// proves exhaustively.
    fn assign_canonical(&self, a: u128, b: u128, c: u128, d: u128, q: u128) -> Vec<Fr> {
        assert!(d < self.modulus, "no complement exists for {d}");
        let mut values = self.assign(a, b, c, d, q);
        let complement = self.modulus - 1 - d;
        values.extend(self.limbs_of(complement));
        let radix = 1u128 << self.width.limb_bits;
        let limb = |v: u128, i: usize| (v >> (self.width.limb_bits * i as u32)) & (radix - 1);
        let mut borrow = 0u128;
        for k in 0..self.width.limbs - 1 {
            borrow = ((limb(d, k) + limb(complement, k) + borrow) >= radix) as u128;
            values.push(fr(borrow));
        }
        values
    }

    /// Whether every carry of an assignment is in `[0, 2^carry_bits)` — the
    /// range check, evaluated rather than looked up.
    fn carries_in_range(&self, values: &[Fr]) -> bool {
        (0..self.width.carries())
            .all(|i| to_u128(values[24 + i]).is_some_and(|v| v < 1u128 << self.carry_bits))
    }
}

// ---------------------------------------------------------------------------
// The congruence
// ---------------------------------------------------------------------------

/// Completeness at a width whose limbs carry real products: for **every**
/// pair of canonical operands, the honest witness satisfies every gate and
/// every carry is in range.
#[test]
fn every_honest_congruence_holds_at_reduced_width() {
    let toy = Toy::SMALL;
    let gates = toy.congruence().gates();
    assert_eq!(gates.len(), toy.width.positions(), "one gate a position");
    let p = toy.modulus;
    for a in 0..p {
        for b in 0..p {
            let c = (a + b) % p;
            let lhs = a * b + c + p;
            let (q, d) = (lhs / p, lhs % p);
            let values = toy.assign(a, b, c, d, q);
            assert!(
                all_hold(&gates, &values),
                "a·b + c ≡ d: a={a} b={b} c={c} failed at {:?}",
                first_failure(&gates, &values)
            );
            assert!(
                toy.carries_in_range(&values),
                "a={a} b={b}: an honest carry left [0, 2^{}) ",
                toy.carry_bits
            );
            assert!(q < 1 << (toy.width.limbs as u32 * toy.width.limb_bits));
        }
    }
}

/// Soundness, exhaustively: over **every** operand triple and **every**
/// candidate result and quotient, the gates plus the carry range admit
/// exactly the residue class — and composing canonicality leaves exactly the
/// honest witness.
///
/// The two halves of that sentence are the two gadgets, and keeping them
/// apart is the point. A congruence proves `d ≡ a·b + c (mod P)` and nothing
/// more: at `P = 13` in a four-bit span, `d` and `d + 13` both satisfy it, and
/// they are *both* honest answers to the question the congruence asks.
/// `docs/spec/ecrecover.md` §3.3's complement is what makes the answer a
/// representative, which is why a value that skips it is a soundness hole and
/// not a missing optimization.
#[test]
fn the_congruence_admits_the_residue_class_and_canonicality_picks_one() {
    let toy = Toy::TINY;
    let gates = toy.congruence().gates();
    let canonical = toy.canonical_result();
    let composed: Vec<(String, GateDef)> = gates.iter().cloned().chain(canonical.gates()).collect();
    let p = toy.modulus;
    let span = 1u128 << (toy.width.limbs as u32 * toy.width.limb_bits);
    for a in 0..p {
        for b in 0..p {
            for c in 0..p {
                let lhs = a * b + c + p;

                // What the congruence alone should admit: every representative
                // of the class that fits the span, with its own quotient.
                let mut want: Vec<(u128, u128)> = (0..span)
                    .filter(|d| (lhs % p) == (d % p) && lhs >= *d)
                    .map(|d| (d, (lhs - d) / p))
                    .filter(|(_, q)| *q < span)
                    .collect();
                want.sort();

                let mut found = Vec::new();
                for d in 0..span {
                    for q in 0..span {
                        let values = toy.assign(a, b, c, d, q);
                        if all_hold(&gates, &values) && toy.carries_in_range(&values) {
                            found.push((d, q));
                        }
                    }
                }
                found.sort();
                assert_eq!(
                    found, want,
                    "a={a} b={b} c={c}: the congruence admitted {found:?}, not {want:?}"
                );

                // Composed with canonicality, exactly one survives, and it is
                // the representative below the modulus.
                let surviving: Vec<(u128, u128)> = found
                    .iter()
                    .copied()
                    .filter(|(d, q)| {
                        *d < p && {
                            let values = toy.assign_canonical(a, b, c, *d, *q);
                            all_hold(&composed, &values) && toy.carries_in_range(&values)
                        }
                    })
                    .collect();
                assert_eq!(
                    surviving,
                    vec![(lhs % p, lhs / p)],
                    "a={a} b={b} c={c}: canonicality left {surviving:?}"
                );
            }
        }
    }
}

/// `docs/spec/ecrecover.md` §3.2, demonstrated rather than asserted: give
/// position 6 an outgoing carry of its own and the congruence stops saying
/// anything at all — results in **no** residue class become reachable.
///
/// A seventh carry is what "writing the term and zeroing it" would leave
/// behind if the zeroing were ever dropped, which is why the gadget does not
/// write it.
#[test]
fn a_seventh_carry_makes_every_congruence_vacuous() {
    let toy = Toy::TINY;
    let honest = toy.congruence().gates();

    // The same gates, with `− radix·t_6` appended to the last position and a
    // seventh carry column at W[30].
    let mut vacuous = honest.clone();
    let last = vacuous.len() - 1;
    let radix = toy.width.radix();
    match &mut vacuous[last].1 {
        GateDef::Quadratic { linear, .. } => {
            linear.push((Coeff::Literal(-radix), PolyAddress::Witness(30)));
        }
        other => panic!("the last position is a Quadratic, not {other:?}"),
    }

    let (a, b, c) = (7u128, 11u128, 3u128);
    let lhs = a * b + c + toy.modulus;
    let class = lhs % toy.modulus;
    let span = 1u128 << 4;

    // A result in the wrong residue class is what must stay out of reach.
    let wrong: Vec<u128> = (0..span).filter(|d| d % toy.modulus != class).collect();
    assert!(!wrong.is_empty(), "the span holds a wrong class");

    let mut reachable = 0;
    for d in wrong.iter().copied() {
        for q in 0..span {
            let mut values = toy.assign(a, b, c, d, q);
            // The seventh carry the chain now leaves free: whatever closes the
            // last position.
            let residue = eval(&honest[honest.len() - 1].1, &values);
            values.push(residue * radix.inverse().unwrap());
            if all_hold(&vacuous, &values) {
                reachable += 1;
            }
        }
    }
    assert!(
        reachable > 0,
        "a free seventh carry must put a wrong residue class in reach, and none was"
    );

    // The gadget as written refuses every one of them.
    for d in wrong {
        for q in 0..span {
            let values = toy.assign(a, b, c, d, q);
            assert!(
                !(all_hold(&honest, &values) && toy.carries_in_range(&values)),
                "the honest gadget admitted d={d} q={q}, which is in the wrong class"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Canonicality
// ---------------------------------------------------------------------------

/// `value < modulus` and nothing weaker: exhaustively over every value a
/// four-limb toy can hold, a complement and a borrow chain exist exactly when
/// the value is below the modulus.
#[test]
fn canonicality_admits_exactly_the_values_below_the_modulus() {
    let toy = Toy::SMALL;
    let w = toy.width;
    let cols = |base: usize| -> Vec<PolyAddress> {
        (0..w.limbs)
            .map(|i| PolyAddress::Witness((base + i) as u32))
            .collect()
    };
    let gadget = Canonical {
        prefix: "toy".into(),
        width: w,
        value: cols(0),
        complement: cols(4),
        modulus: cols(8),
        borrows: (0..w.limbs - 1)
            .map(|i| PolyAddress::Witness((12 + i) as u32))
            .collect(),
    };
    let gates = gadget.gates();
    let span = 1u128 << (w.limbs as u32 * w.limb_bits);
    let radix = 1u128 << w.limb_bits;

    for value in 0..span {
        // The honest complement, if the value is below the modulus.
        let admitted = value < toy.modulus;
        let complement = if admitted {
            toy.modulus - 1 - value
        } else {
            continue;
        };
        let mut values: Vec<Fr> = Vec::new();
        values.extend(toy.limbs_of(value));
        values.extend(toy.limbs_of(complement));
        values.extend(toy.limbs_of(toy.modulus));
        // The borrows, solved limb by limb over the integers.
        let vl: Vec<u128> = (0..w.limbs)
            .map(|i| (value >> (w.limb_bits * i as u32)) & (radix - 1))
            .collect();
        let cl: Vec<u128> = (0..w.limbs)
            .map(|i| (complement >> (w.limb_bits * i as u32)) & (radix - 1))
            .collect();
        let ml: Vec<u128> = (0..w.limbs)
            .map(|i| ((toy.modulus - 1) >> (w.limb_bits * i as u32)) & (radix - 1))
            .collect();
        let mut borrow = 0u128;
        let mut borrows = Vec::new();
        for k in 0..w.limbs - 1 {
            let sum = vl[k] + cl[k] + borrow;
            let out = (sum >= radix) as u128;
            assert_eq!(sum - radix * out, ml[k], "the complement is limb-exact");
            borrows.push(fr(out));
            borrow = out;
        }
        values.extend(borrows);
        assert!(
            all_hold(&gates, &values),
            "value={value} is below the modulus and was refused at {:?}",
            first_failure(&gates, &values)
        );
    }

    // And no value at or above the modulus has any complement at all: search
    // every complement and every borrow pattern for one.
    for value in toy.modulus..span {
        for complement in 0..span {
            for pattern in 0..1u128 << (w.limbs - 1) {
                let mut values: Vec<Fr> = Vec::new();
                values.extend(toy.limbs_of(value));
                values.extend(toy.limbs_of(complement));
                values.extend(toy.limbs_of(toy.modulus));
                values.extend((0..w.limbs - 1).map(|i| fr((pattern >> i) & 1)));
                assert!(
                    !all_hold(&gates, &values),
                    "value={value} is at or above the modulus and was admitted with \
                     complement={complement} borrows={pattern:b}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Halves
// ---------------------------------------------------------------------------

/// The 6-to-1 collision `docs/spec/ecrecover.md` §3.4 names, at the real
/// width: six canonical secp256k1 values whose limbs recompose to zero in
/// `Fr`, and the 128-bit halves that separate them.
#[test]
fn a_whole_value_collides_in_fr_and_its_halves_do_not() {
    let w = Width::SECP256K1;
    let p = constants::secp256k1::P;
    let modulus = u256_of(&p);

    // |Fr|, as an integer.
    let order = to_u256(&(Fr::ZERO - Fr::ONE).to_bytes()).add(&U256::from_u64(1));

    let mut collisions = Vec::new();
    let mut k = 0u32;
    loop {
        let v = order.checked_mul_small(k);
        let Some(v) = v else { break };
        if v >= modulus {
            break;
        }
        collisions.push(v);
        k += 1;
    }
    assert_eq!(
        collisions.len(),
        6,
        "p / |Fr| = 5, so six multiples of |Fr| are canonical"
    );

    // Whole-value recomposition sends every one of them to zero.
    for v in &collisions {
        let limbs = v.limbs();
        let whole = (0..w.limbs).rev().fold(Fr::ZERO, |acc, i| {
            acc * constraints::nonnative::two_pow(64) + Fr::from_u64(limbs[i])
        });
        assert_eq!(
            whole,
            Fr::ZERO,
            "{v:?} does not collide, and the test is wrong"
        );
    }

    // The halves do not: two limbs a half, each below 2^128.
    assert_eq!(
        half_limbs(w),
        2,
        "a 64-bit limb gives two limbs a 128-bit half"
    );
    let cols: Vec<PolyAddress> = (0..w.limbs)
        .map(|i| PolyAddress::Witness(i as u32))
        .collect();
    let mut seen = std::collections::HashSet::new();
    for v in &collisions {
        let limbs = v.limbs();
        let values: Vec<Fr> = limbs.iter().map(|l| Fr::from_u64(*l)).collect();
        let halves: Vec<[u8; 32]> = (0..2)
            .map(|h| {
                let form = half(w, &cols, h);
                form.iter()
                    .fold(Fr::ZERO, |acc, (c, a)| {
                        let Coeff::Literal(c) = c else { unreachable!() };
                        acc + *c * read(&values, *a)
                    })
                    .to_bytes()
            })
            .collect();
        assert!(
            seen.insert(halves),
            "two of the six collisions share both halves, which cannot be"
        );
    }
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// A bound's chunks and bits recompose, its bits are held boolean, and the
/// width it proves is the one it claims.
#[test]
fn a_bound_is_exactly_as_wide_as_it_says() {
    let w = Width::SECP256K1;
    let bound = Bound {
        prefix: "carry".into(),
        value: PolyAddress::Witness(0),
        chunks: (1..5).map(PolyAddress::Witness).collect(),
        bits: (5..9).map(PolyAddress::Witness).collect(),
        selector: PolyAddress::Witness(9),
    };
    assert_eq!(
        bound.bits_bounded(w),
        68,
        "four 16-bit chunks and four bits"
    );
    let gates = bound.gates(w);
    assert_eq!(
        gates.len(),
        5,
        "one recomposition and four booleanity gates"
    );
    assert_eq!(bound.lookups().len(), 4, "a bit carries no obligation");

    // A value and its honest decomposition.
    let value = (1u128 << 67) + (1 << 40) + 7;
    let mut values = vec![fr(value)];
    for j in 0..4 {
        values.push(fr((value >> (16 * j)) & 0xffff));
    }
    for j in 0..4 {
        values.push(fr((value >> (64 + j)) & 1));
    }
    values.push(Fr::ONE);
    assert!(
        all_hold(&gates, &values),
        "the honest decomposition failed at {:?}",
        first_failure(&gates, &values)
    );

    // One chunk short by one, and the recomposition refuses it.
    values[1] -= Fr::ONE;
    assert!(!all_hold(&gates, &values));
}

/// The magnitude argument of `docs/spec/ecrecover.md` §3.2, in exact
/// integers rather than in prose — the one claim the reduced widths above
/// cannot make, and the one every congruence in this family rests on.
///
/// A position's value must stay far enough below `|Fr|` that its equation,
/// read as a statement about integers, has a unique representative: that is
/// what lets seven equations in `Fr` be multiplied by `2^(64k)` and summed
/// into one identity over ℤ. And the carry it induces must fit the 68 bits
/// the range check gives it.
///
/// Both are tight, and the carry is the tighter. `8·(2^64 − 1)² =
/// 2^131 − 2^68 + 8`, so a position sits just under `2^131` and its carry
/// just under `2^67` — inside the range check's 68 bits by one bit, which is
/// the sign. A third product a position overflows it, and the last assertion
/// here is that it does.
#[test]
fn a_position_stays_inside_the_carry_and_inside_the_field() {
    let w = Width::SECP256K1;
    let limb_max = U256::from_u64(u64::MAX);

    // The family's shape: two products a position — the operand product and
    // the quotient-times-modulus product — at most three addends, and `K = 1`
    // times the modulus.
    const PRODUCTS: u32 = 2;
    const ADDENDS: u32 = 3;
    const CARRY_BITS: u32 = 68;

    // Position `limbs − 1` is the widest: every one of a product's `limbs`
    // pairs lands there.
    let pairs = PRODUCTS * w.limbs as u32;
    let mut bound = U256::from_u64(0);
    for _ in 0..pairs {
        bound = bound.add(&limb_max.mul(&limb_max));
    }
    for _ in 0..ADDENDS + 1 {
        bound = bound.add(&limb_max);
    }
    // The carry coming in, at its own bound.
    bound = bound.add(&U256::two_pow(CARRY_BITS - 1));

    // The carry going out is that over the radix, and it must fit the range
    // check's 68 bits with a sign bit to spare.
    let carry_out = bound.shr(w.limb_bits);
    assert!(
        carry_out.less(&U256::two_pow(CARRY_BITS - 1)),
        "a carry of up to {carry_out:?} does not fit [0, 2^{CARRY_BITS}) after its offset"
    );

    // And the position itself is far below |Fr|/2, so its `Fr` equation is an
    // integer equation. |Fr| is about 2^254.
    let order = to_u256(&(Fr::ZERO - Fr::ONE).to_bytes()).add(&U256::from_u64(1));
    assert!(
        bound.add(&U256::two_pow(CARRY_BITS)).less(&order.shr(1)),
        "a position reaches |Fr|/2 and the lift to ℤ fails"
    );
    // Where the bound actually sits, stated as the power of two it is: just
    // **under** `2^131`, because `8·(2^64 − 1)² = 2^131 − 2^68 + 8` and the
    // addends and the incoming carry together do not make up the `2^68`.
    assert!(bound.less(&U256::two_pow(131)), "the bound is under 2^131");
    assert!(!bound.less(&U256::two_pow(130)), "and over 2^130");

    // One more product a position and the carry stops fitting — the reason
    // the shape allows two and the gadget's doc says so.
    let mut overfull = bound;
    for _ in 0..w.limbs {
        overfull = overfull.add(&limb_max.mul(&limb_max));
    }
    assert!(
        !overfull
            .shr(w.limb_bits)
            .less(&U256::two_pow(CARRY_BITS - 1)),
        "a third product a position must overflow the carry, and it did not"
    );
}

// ---------------------------------------------------------------------------
// A 256-bit integer, for the collision test alone
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct U256([u64; 4]);

impl U256 {
    fn limbs(&self) -> [u64; 4] {
        self.0
    }

    fn from_u64(v: u64) -> U256 {
        U256([v, 0, 0, 0])
    }

    fn two_pow(bits: u32) -> U256 {
        assert!(bits < 256);
        let mut out = [0u64; 4];
        out[(bits / 64) as usize] = 1u64 << (bits % 64);
        U256(out)
    }

    fn add(&self, other: &U256) -> U256 {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (i, o) in out.iter_mut().enumerate() {
            let wide = self.0[i] as u128 + other.0[i] as u128 + carry;
            *o = wide as u64;
            carry = wide >> 64;
        }
        assert_eq!(carry, 0, "this test's bounds do not reach 2^256");
        U256(out)
    }

    fn mul(&self, other: &U256) -> U256 {
        let mut out = [0u64; 4];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 - i {
                let wide = out[i + j] as u128 + self.0[i] as u128 * other.0[j] as u128 + carry;
                out[i + j] = wide as u64;
                carry = wide >> 64;
            }
            assert_eq!(carry, 0, "this test's bounds do not reach 2^256");
        }
        U256(out)
    }

    /// `self >> bits`, for `bits` up to one whole limb.
    fn shr(&self, bits: u32) -> U256 {
        assert!(bits <= 64);
        if bits == 64 {
            return U256([self.0[1], self.0[2], self.0[3], 0]);
        }
        if bits == 0 {
            return *self;
        }
        let mut out = [0u64; 4];
        for (i, o) in out.iter_mut().enumerate() {
            *o = self.0[i] >> bits;
            if i + 1 < 4 {
                *o |= self.0[i + 1] << (64 - bits);
            }
        }
        U256(out)
    }

    fn less(&self, other: &U256) -> bool {
        for i in (0..4).rev() {
            if self.0[i] != other.0[i] {
                return self.0[i] < other.0[i];
            }
        }
        false
    }
    /// `self · k` for a small `k`, or `None` on overflow.
    fn checked_mul_small(&self, k: u32) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (i, o) in out.iter_mut().enumerate() {
            let wide = self.0[i] as u128 * k as u128 + carry;
            *o = wide as u64;
            carry = wide >> 64;
        }
        (carry == 0).then_some(U256(out))
    }
}

fn u256_of(limbs: &[u64; 4]) -> U256 {
    U256(*limbs)
}

fn to_u256(bytes: &[u8; 32]) -> U256 {
    let mut out = [0u64; 4];
    for (i, o) in out.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[8 * i..8 * i + 8]);
        *o = u64::from_le_bytes(b);
    }
    U256(out)
}
