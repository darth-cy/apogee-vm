//! BN254's base field tower level one, and both curve groups.
//!
//! The full tower, both curve groups, the optimal ate pairing, and the
//! Pippenger multi-scalar multiplication the prover leans on.
//!
//! ```text
//!   Fq   = GF(q),           q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
//!   Fq2  = Fq[u]/(u^2 + 1)
//!   Fq6  = Fq2[v]/(v^3 - xi),   xi = 9 + u
//!   Fq12 = Fq6[w]/(w^2 - v)
//!   G1   = E /Fq  : y^2 = x^3 + 3            #E(Fq)   = r,            cofactor 1
//!   G2   = E'/Fq2 : y^2 = x^3 + 3/(9+u)      #E'(Fq2) = r * (2q - r), cofactor 2q - r
//!   e    : G1 x G2 -> Fq12                   the optimal ate pairing, in `pairing`
//! ```
//!
//! `r` is `field::Fr`'s modulus: the scalar field. Scalars are `Fr`, and
//! coordinates are `Fq`. The two moduli agree in their top 128 bits, so they
//! are easy to confuse by eye and hard to confuse by type.
//!
//! # Point wire format
//!
//! Uncompressed affine, one canonical spelling, and the same rule as every
//! other field element that reaches a file or a transcript: **canonical
//! (non-Montgomery) 32-byte little-endian per `Fq`**.
//!
//! ```text
//!   G1Affine   64 bytes   x || y
//!   G2Affine  128 bytes   x.c0 || x.c1 || y.c0 || y.c1
//!   infinity             all bytes zero
//! ```
//!
//! The all-zero encoding is unambiguous in both groups because `(0, 0)` is off
//! the curve: `0 != 3` in G1, and `0 != 3/(9+u)` in G2. `from_bytes` validates
//! canonicity, the curve equation and subgroup membership, and returns `None`
//! rather than panicking on any failure. There is no compressed form, and no
//! decompression, anywhere in the protocol.
//!
//! Note that this byte form is *not* how a point enters a transcript: the
//! frozen rule there is four ~128-bit `Fr` limbs per point, which is a later
//! stage's business.
//!
//! # Numbers this crate relies on
//!
//! Each is re-derived in `tests/constants_check.rs` rather than trusted:
//!
//! - `q = 3 mod 4`, so a square root is one exponentiation by `(q+1)/4`.
//! - `-1` is a nonresidue mod `q`. This is what makes `u^2 = -1` a valid
//!   extension and what makes [`Fq2::sqrt`]'s two branches exhaustive.
//! - `#E(Fq) = r` is an odd prime: G1's cofactor is 1, so on-curve implies
//!   in-subgroup, and no on-curve point has `y = 0`.
//! - `2q - r` is odd, so `#E'(Fq2)` is odd too: the twist has no 2-torsion
//!   either. G2's cofactor is not 1, so its subgroup check is real arithmetic.

mod fq;
mod fq12;
mod fq2;
mod fq6;
mod g1;
mod g2;
pub mod msm;
pub mod pairing;

pub use fq::{batch_inverse, Fq};
pub use fq12::Fq12;
pub use fq2::Fq2;
pub use fq6::Fq6;
pub use g1::{G1Affine, G1Projective};
pub use g2::{G2Affine, G2Projective};
