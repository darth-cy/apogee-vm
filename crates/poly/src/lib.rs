#![no_std]
//! Multilinear polynomials over `Fr`, with small-type backing and a lazy lift.
//!
//! # The index convention (frozen)
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
//! Every later circuit stage builds on that convention. It is checked against
//! arkworks' `DenseMultilinearExtension` in `tests/differential.rs`, which
//! agrees on both halves of it.
//!
//! # Small-type backing
//!
//! Trace columns are mostly narrow integers — bits, bytes, u32 words — so a
//! column stays at its native width, cheap to fill during trace generation,
//! until a challenge forces field arithmetic. *Lazy* means bind-triggered:
//! [`MultilinearPoly::get`] and [`MultilinearPoly::evaluate`] lift on the fly
//! and leave the backing alone; the first [`MultilinearPoly::bind`] lifts the
//! whole table to [`PolyBacking::Fr`], and it stays there. There are never two
//! representations of one polynomial.
//!
//! Lift is the canonical embedding of the integer into `Fr`: a `U1` bit becomes
//! `Fr::ZERO` or `Fr::ONE`, a `U8`/`U16`/`U32` word becomes `Fr::from_u64`.

extern crate alloc;

use alloc::vec::Vec;

use field::Fr;

/// How a polynomial's evaluation table is stored.
///
/// The four small variants exist to keep trace columns at their native width;
/// see the module docs. All five behave identically once read.
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
    Fr(Vec<Fr>),
}

impl PolyBacking {
    /// The number of evaluations stored, whatever the width.
    fn entries(&self) -> usize {
        match self {
            PolyBacking::U1(_, entries) => *entries,
            PolyBacking::U8(v) => v.len(),
            PolyBacking::U16(v) => v.len(),
            PolyBacking::U32(v) => v.len(),
            PolyBacking::Fr(v) => v.len(),
        }
    }

    /// The single definition of the lift: entry `index`, embedded in `Fr`.
    fn entry(&self, index: usize) -> Fr {
        match self {
            PolyBacking::U1(limbs, _) => {
                if (limbs[index / 64] >> (index % 64)) & 1 == 1 {
                    Fr::ONE
                } else {
                    Fr::ZERO
                }
            }
            PolyBacking::U8(v) => Fr::from_u64(v[index] as u64),
            PolyBacking::U16(v) => Fr::from_u64(v[index] as u64),
            PolyBacking::U32(v) => Fr::from_u64(v[index] as u64),
            PolyBacking::Fr(v) => v[index],
        }
    }

    /// The whole table, lifted. Used by `bind`, which must leave the backing in
    /// the `Fr` variant.
    fn lift(&self) -> Vec<Fr> {
        (0..self.entries()).map(|i| self.entry(i)).collect()
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

    /// The evaluation at a cube vertex, lifted on the fly if the backing is
    /// still small. Does not mutate the backing.
    pub fn get(&self, index: usize) -> Fr {
        assert!(
            index < self.len(),
            "MultilinearPoly::get: index {index} is out of range for {} evaluations",
            self.len()
        );
        self.backing.entry(index)
    }

    /// Fix the current variable 0 to `r`, halving the table. The first call
    /// lifts the whole backing to [`PolyBacking::Fr`], where it stays.
    pub fn bind(&mut self, r: Fr) {
        assert!(
            self.num_vars > 0,
            "MultilinearPoly::bind: the polynomial has no variables left to bind"
        );
        // Take the backing so an `Fr` table can be folded in place; anything
        // else is lifted first, which is must-be-exact 2.
        let mut values = match core::mem::replace(&mut self.backing, PolyBacking::Fr(Vec::new())) {
            PolyBacking::Fr(v) => v,
            small => small.lift(),
        };
        let half = values.len() / 2;
        for i in 0..half {
            let lo = values[2 * i];
            let hi = values[2 * i + 1];
            values[i] = lo + r * (hi - lo);
        }
        values.truncate(half);
        self.backing = PolyBacking::Fr(values);
        self.num_vars -= 1;
    }

    /// The value off the cube at `point`, where `point[j]` is variable `j`.
    /// Non-destructive: it folds a scratch table and never touches the backing.
    pub fn evaluate(&self, point: &[Fr]) -> Fr {
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
        // The first round lifts on the fly, exactly as `get` does.
        let r = point[0];
        let mut scratch: Vec<Fr> = (0..self.len() / 2)
            .map(|i| {
                let lo = self.backing.entry(2 * i);
                let hi = self.backing.entry(2 * i + 1);
                lo + r * (hi - lo)
            })
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

    /// The live backing. After any `bind` it is always [`PolyBacking::Fr`],
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
pub fn eq_table(r: &[Fr]) -> Vec<Fr> {
    let mut table: Vec<Fr> = Vec::new();
    table.push(Fr::ONE);
    for (j, &rj) in r.iter().enumerate() {
        let half = 1usize << j;
        table.resize(2 * half, Fr::ZERO);
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
pub fn eq_eval(r: &[Fr], y: &[Fr]) -> Fr {
    assert_eq!(
        r.len(),
        y.len(),
        "eq_eval: r has {} coordinates, y has {}",
        r.len(),
        y.len()
    );
    let mut acc = Fr::ONE;
    for (&rj, &yj) in r.iter().zip(y.iter()) {
        acc *= rj * yj + (Fr::ONE - rj) * (Fr::ONE - yj);
    }
    acc
}
