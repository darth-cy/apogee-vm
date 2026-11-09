#![no_std]
//! Multilinear polynomials: committed columns over the base field `Fp` at
//! their native width, bound tables over the challenge field `Fp2`.
//!
//! # The index convention
//!
//! A polynomial in `n` variables is a table of `2^n` evaluations over the
//! boolean hypercube `{0,1}^n`. **Variable `j` is bit `j` of the index**, so
//! the evaluation at `y = (y_0, ..., y_{n-1})` sits at
//! `index = sum_j y_j * 2^j` — little-endian, variable 0 in the low bit. For
//! `n = 3`, `get(0b011)` is the evaluation at `y_0 = 1, y_1 = 1, y_2 = 0`.
//!
//! [`MultilinearPoly::bind`] fixes **variable 0**, the lowest bit, halving the
//! table by `f'(i) = f(2i) + r * (f(2i+1) - f(2i))`. The old variable 1 then
//! becomes the new variable 0, so binding `r_0, r_1, ...` in order fixes the
//! variables in order and leaves `evaluate(&[r_0, r_1, ...])` in the last cell.
//!
//! Every circuit builds on that convention. It is checked against
//! arkworks' `DenseMultilinearExtension` in `tests/differential.rs`, which
//! agrees on both halves of it.
//!
//! # Small-type backing
//!
//! Trace columns are mostly narrow integers — bits, bytes, u32 words — so a
//! column stays at its native width, cheap to fill during trace generation,
//! until a challenge forces field arithmetic. A column no integer width holds
//! is [`PolyBacking::Fp`]. *Lazy* means bind-triggered:
//! [`MultilinearPoly::get`] and [`MultilinearPoly::evaluate`] lift on the fly
//! and leave the backing alone; the first [`MultilinearPoly::bind`], at a
//! challenge in `Fp2`, lifts the table to [`PolyBacking::Fp2`] — folding the
//! base table straight into a half-size `Fp2` one, in mixed arithmetic — and it
//! stays there. There are never two representations of one polynomial.
//!
//! Lift is the canonical embedding of the integer into `Fp`, and of `Fp` into
//! `Fp2`: a `U1` bit becomes 0 or 1, a `U8`/`U16`/`U32` word `Fp::from_u64`.
//! [`MultilinearPoly::get_base`] reads a base table without the second step.

extern crate alloc;

use alloc::vec::Vec;

use field_a64_c5::{Fp, Fp2};

/// How a polynomial's evaluation table is stored.
///
/// The four small variants exist to keep trace columns at their native width;
/// see the module docs. Every variant but `Fp2` is a **base** table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolyBacking {
    /// One bit per evaluation: the `Vec<u64>` limbs, then the entry count.
    ///
    /// Entry `i` is bit `i % 64` of limb `i / 64`, little-endian to match the
    /// index convention. The count fixes `num_vars`; there are exactly
    /// `count.div_ceil(64)` limbs and the bits past the count in the final limb
    /// are zero. [`MultilinearPoly::new`] enforces all three.
    U1(Vec<u64>, usize),
    U8(Vec<u8>),
    U16(Vec<u16>),
    U32(Vec<u32>),
    /// Full base-field values: a committed column no integer width holds.
    Fp(Vec<Fp>),
    /// Challenge-field values: a bound table, or a layer the GKR forward pass
    /// wrote.
    Fp2(Vec<Fp2>),
}

impl PolyBacking {
    /// The number of evaluations stored, whatever the width.
    fn entries(&self) -> usize {
        match self {
            PolyBacking::U1(_, entries) => *entries,
            PolyBacking::U8(v) => v.len(),
            PolyBacking::U16(v) => v.len(),
            PolyBacking::U32(v) => v.len(),
            PolyBacking::Fp(v) => v.len(),
            PolyBacking::Fp2(v) => v.len(),
        }
    }

    /// The single definition of the lift into `Fp`: entry `index` of a base
    /// table. Panics on an `Fp2` one.
    fn base(&self, index: usize) -> Fp {
        match self {
            PolyBacking::U1(limbs, _) => Fp::from_u64((limbs[index / 64] >> (index % 64)) & 1),
            PolyBacking::U8(v) => Fp::from_u64(v[index] as u64),
            PolyBacking::U16(v) => Fp::from_u64(v[index] as u64),
            PolyBacking::U32(v) => Fp::from_u64(v[index] as u64),
            PolyBacking::Fp(v) => v[index],
            PolyBacking::Fp2(_) => panic!("an Fp2 table has no base value"),
        }
    }

    /// Entry `index`, embedded in `Fp2`.
    fn entry(&self, index: usize) -> Fp2 {
        match self {
            PolyBacking::Fp2(v) => v[index],
            base => base.base(index).into(),
        }
    }

    /// Entry `i` of the table bound at `r`, `f(2i) + r·(f(2i+1) − f(2i))`: in
    /// mixed arithmetic for a base table, where `r` meets a base difference.
    fn fold(&self, i: usize, r: Fp2) -> Fp2 {
        match self {
            PolyBacking::Fp2(v) => v[2 * i] + r * (v[2 * i + 1] - v[2 * i]),
            base => {
                let lo = base.base(2 * i);
                r * (base.base(2 * i + 1) - lo) + lo
            }
        }
    }
}

/// A multilinear polynomial, stored as its evaluations over `{0,1}^num_vars`.
#[derive(Clone, Debug)]
pub struct MultilinearPoly {
    backing: PolyBacking,
    /// Always equal to `log2(backing.entries())`; `bind` decrements it and
    /// truncates the table in the same breath.
    num_vars: usize,
}

impl MultilinearPoly {
    /// Panics unless the backing holds a power-of-two number of evaluations,
    /// and — for [`PolyBacking::U1`] — unless the bitset is well formed.
    pub fn new(backing: PolyBacking) -> MultilinearPoly {
        let entries = backing.entries();
        assert!(
            entries.is_power_of_two(),
            "MultilinearPoly::new: backing holds {entries} evaluations, which is not a power of two"
        );
        if let PolyBacking::U1(limbs, _) = &backing {
            assert_eq!(
                limbs.len(),
                entries.div_ceil(64),
                "PolyBacking::U1: {entries} entries need {} limbs, got {}",
                entries.div_ceil(64),
                limbs.len()
            );
            let used = entries - 64 * (limbs.len() - 1);
            if used < 64 {
                assert_eq!(
                    limbs[limbs.len() - 1] >> used,
                    0,
                    "PolyBacking::U1: bits past entry {entries} must be zero"
                );
            }
        }
        MultilinearPoly {
            backing,
            num_vars: entries.trailing_zeros() as usize,
        }
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// `2^num_vars`: the size of the remaining cube. Never zero.
    // A polynomial always has at least one evaluation, so an `is_empty` beside
    // this would be a constant `false` with no caller.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        1usize << self.num_vars
    }

    /// The evaluation at a cube vertex, lifted on the fly into `Fp2` if the
    /// backing is base. Does not mutate the backing.
    pub fn get(&self, index: usize) -> Fp2 {
        self.check(index, "get");
        self.backing.entry(index)
    }

    /// The evaluation at a cube vertex of a base table. Panics on an `Fp2`
    /// table: a bound one, or a layer above the base.
    pub fn get_base(&self, index: usize) -> Fp {
        self.check(index, "get_base");
        self.backing.base(index)
    }

    fn check(&self, index: usize, what: &str) {
        assert!(
            index < self.len(),
            "MultilinearPoly::{what}: index {index} is out of range for {} evaluations",
            self.len()
        );
    }

    /// Fix the current variable 0 to `r`, halving the table. The first call
    /// lifts the backing to [`PolyBacking::Fp2`], where it stays.
    pub fn bind(&mut self, r: Fp2) {
        assert!(
            self.num_vars > 0,
            "MultilinearPoly::bind: the polynomial has no variables left to bind"
        );
        let half = self.len() / 2;
        // Take the backing so an `Fp2` table can be folded in place. A base
        // one is folded straight into a half-size `Fp2` table, so no full-size
        // lifted copy is ever made.
        let values = match core::mem::replace(&mut self.backing, PolyBacking::Fp2(Vec::new())) {
            PolyBacking::Fp2(mut values) => {
                for i in 0..half {
                    let lo = values[2 * i];
                    values[i] = lo + r * (values[2 * i + 1] - lo);
                }
                values.truncate(half);
                values
            }
            base => (0..half).map(|i| base.fold(i, r)).collect(),
        };
        self.backing = PolyBacking::Fp2(values);
        self.num_vars -= 1;
    }

    /// The value off the cube at `point`, where `point[j]` is variable `j`.
    /// Non-destructive: it folds a scratch table and never touches the backing.
    pub fn evaluate(&self, point: &[Fp2]) -> Fp2 {
        assert_eq!(
            point.len(),
            self.num_vars,
            "MultilinearPoly::evaluate: point has {} coordinates, expected {}",
            point.len(),
            self.num_vars
        );
        if self.num_vars == 0 {
            return self.get(0);
        }
        // The first round lifts on the fly, exactly as `bind` does.
        let r = point[0];
        let mut scratch: Vec<Fp2> = (0..self.len() / 2)
            .map(|i| self.backing.fold(i, r))
            .collect();
        for &r in &point[1..] {
            let half = scratch.len() / 2;
            for i in 0..half {
                let lo = scratch[2 * i];
                let hi = scratch[2 * i + 1];
                scratch[i] = lo + r * (hi - lo);
            }
            scratch.truncate(half);
        }
        scratch[0]
    }

    /// The live backing. After any `bind` it is always [`PolyBacking::Fp2`],
    /// which is what makes the lazy lift observable from a test.
    pub fn backing(&self) -> &PolyBacking {
        &self.backing
    }
}

/// `eq(r, y)` for every `y` in `{0,1}^r.len()`, indexed by the same convention
/// as a polynomial's table: `y` sits at `sum_j y_j * 2^j`.
///
/// Built by iterative doubling — one multiplication per new entry, so `2^n - 1`
/// in total.
pub fn eq_table(r: &[Fp2]) -> Vec<Fp2> {
    let mut table: Vec<Fp2> = Vec::new();
    table.push(Fp2::ONE);
    for (j, &rj) in r.iter().enumerate() {
        let half = 1usize << j;
        table.resize(2 * half, Fp2::ZERO);
        for i in 0..half {
            // Variable j is bit j, so `y_j = 1` lands `half` further along.
            let v = table[i];
            let with_one = v * rj;
            table[i + half] = with_one;
            table[i] = v - with_one;
        }
    }
    table
}

/// `eq(r, y) = prod_j (r_j * y_j + (1 - r_j) * (1 - y_j))`, off the cube in
/// both arguments. `O(n)`, and symmetric in `r` and `y`.
pub fn eq_eval(r: &[Fp2], y: &[Fp2]) -> Fp2 {
    assert_eq!(
        r.len(),
        y.len(),
        "eq_eval: r has {} coordinates, y has {}",
        r.len(),
        y.len()
    );
    let mut acc = Fp2::ONE;
    for (&rj, &yj) in r.iter().zip(y.iter()) {
        acc *= rj * yj + (Fp2::ONE - rj) * (Fp2::ONE - yj);
    }
    acc
}
