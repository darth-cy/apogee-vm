//! The witnessed-inverse **is-zero** test the execution families share
//! (`docs/spec/jump-branch-slt.md` §3.1). The x0 rule is built on it, the
//! jump/branch/slt family's equality, and `MUL_DIV`'s `r = 0` and zero-divisor
//! tests. The 64-bit comparison is `crate::family::Family::compare64`.

use alloc::vec;

use field::Fp;

use crate::{Coeff, GateDef, PolyAddress};

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fp::from_u64(v))
}

/// The witnessed-inverse is-zero gadget over the linear form
/// `x = Σ c_i·x_i`, with witness columns `inv` and `z`:
///
/// ```text
/// x·inv + z − enable = 0
/// z·x = 0
/// ```
///
/// Where `enable` is 0 or 1 — which the caller establishes — the two force
/// `z = enable·[x = 0]`: at `x ≠ 0` the second gives `z = 0` and the first
/// `inv = enable/x`; at `x = 0` the first gives `z = enable`. So `z` is
/// boolean with no gate of its own, and a row whose `enable` is 0 has
/// `z = 0`, which keeps the all-zero row valid. Both gates are degree 2.
///
/// The x0 rule is this over `x = addr`, enabled by the `rd` query's mask
/// (`docs/spec/memory.md` §2.4).
pub fn is_zero(
    x: &[(Coeff, PolyAddress)],
    inv: PolyAddress,
    z: PolyAddress,
    enable: PolyAddress,
) -> [GateDef; 2] {
    [
        GateDef::Quadratic {
            constant: lit(0),
            linear: vec![(lit(1), z), (Coeff::Literal(Fp::MINUS_ONE), enable)],
            products: x.iter().map(|(c, v)| (*c, *v, inv)).collect(),
        },
        GateDef::Quadratic {
            constant: lit(0),
            linear: vec![],
            products: x.iter().map(|(c, v)| (*c, *v, z)).collect(),
        },
    ]
}
