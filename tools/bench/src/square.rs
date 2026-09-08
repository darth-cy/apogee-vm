//! The instance both zerocheck routines run on: `A * A - B = 0`, with `A` a
//! `u16` column and `B = A^2` a `u32` one. It is S04 acceptance 1's witness,
//! so the prove number and the verify comparison are measured over the same
//! claim.

use field::Fr;
use poly::{MultilinearPoly, PolyBacking};
use sumcheck::{Gate, GateTerm, PolyAddress};
use test_support::Rng;

use crate::timing::SEED;

/// A satisfying witness and the gate that vanishes on it.
pub struct Square {
    pub gate: Gate,
    a: Vec<u16>,
    b: Vec<u32>,
}

impl Square {
    /// `2^n_vars` rows, deterministic in `n_vars`. `A` is uniform in `u16` so
    /// `B = A^2` fits a `u32` exactly, which is why the two columns get the
    /// backings they do.
    pub fn new(n_vars: usize) -> Square {
        let mut rng = Rng::new(SEED ^ 0x5330_3400);
        let a: Vec<u16> = (0..1usize << n_vars)
            .map(|_| rng.next_u64() as u16)
            .collect();
        let b: Vec<u32> = a.iter().map(|&x| (x as u32) * (x as u32)).collect();

        // `A * A + (-1) * B`. The square is a term naming input 0 twice.
        let addr_a = PolyAddress(0);
        let addr_b = PolyAddress(1);
        let gate = Gate::new(
            &[&addr_a, &addr_b],
            vec![
                GateTerm {
                    coef: Fr::ONE,
                    a: 0,
                    b: Some(0),
                },
                GateTerm {
                    coef: Fr::MINUS_ONE,
                    a: 1,
                    b: None,
                },
            ],
        )
        .expect("two distinct inputs, both terms in range");

        Square { gate, a, b }
    }

    pub fn rows(&self) -> usize {
        self.a.len()
    }

    /// A fresh pair of columns in the gate's declaration order.
    /// `prove_zerocheck` consumes what it is handed, so every run needs its
    /// own; the clone is why routines build these outside their timed regions.
    pub fn columns(&self) -> Vec<MultilinearPoly> {
        vec![
            MultilinearPoly::new(PolyBacking::U16(self.a.clone())),
            MultilinearPoly::new(PolyBacking::U32(self.b.clone())),
        ]
    }

    /// Both columns lifted to `Fr`: the naive verifier's view of the witness.
    pub fn lifted(&self) -> (Vec<Fr>, Vec<Fr>) {
        (
            self.a.iter().map(|&x| Fr::from_u64(x as u64)).collect(),
            self.b.iter().map(|&x| Fr::from_u64(x as u64)).collect(),
        )
    }
}
