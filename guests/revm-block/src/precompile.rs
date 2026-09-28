//! S26c's routing of Ethereum's `0x02`, `0x06` and `0x07` precompiles through
//! this VM's delegation circuits, by way of revm's `install_crypto` hook.
//!
//! # Why this hook and not a vendored crate
//!
//! The `Crypto` trait is revm's own seam for exactly this: every default method
//! is the software implementation and an installed provider replaces the ones it
//! overrides. Nothing is vendored, nothing is patched, and the trait's other
//! fourteen methods keep their upstream bodies — so `0x01`, `0x05`, `0x08` and
//! the rest are untouched, and `ecrecover` in particular still runs `k256`,
//! whose *internal* point arithmetic is where S26c's secp256k1 acceleration
//! lands (`guests/vendor/k256`).
//!
//! **The provider is installed on the guest target alone.** On the host this
//! module's [`g1_add`] and [`g1_mul`] are arkworks and nothing is installed at
//! all, so `crates/emulator/tests/revm.rs`' native-revm oracle runs upstream's
//! code — which is the only reason that oracle is worth anything.
//!
//! # What is delegated, and what that is worth
//!
//! - **`sha256`** is [`guest_sdk::sha256`]: one `SHA256_COMP` invocation per
//!   64-byte block, with the padding and the block loop in guest code.
//! - **`bn254_g1_mul`** is a double-and-add ladder over `EC_ADD`. Algorithm 7
//!   is complete, so the ladder starts at the identity and branches on nothing:
//!   about 254 doublings and 127 additions, three invocations each.
//! - **`bn254_g1_add`** is one addition, three invocations.
//!
//! **The addition is the modest one and it is worth saying why.** The
//! precompile's boundary is *affine*, so whatever computes the sum, the result
//! has to be normalized — one modular inversion, some three hundred field
//! multiplications, which dominates the twelve the group law costs either way.
//! Routing it therefore replaces about 5% of that precompile's work. The
//! multiplication is the opposite case: its ~380 point operations are about
//! 3,000 field multiplications against one inversion, so the ladder is where
//! the delegation earns its place.
//!
//! # Parsing is upstream's, deliberately
//!
//! [`read_g1_point`] and [`encode_g1_point`] mirror
//! `revm_precompile::bn254::arkworks`, whose own versions are `pub(super)` and
//! out of reach. A divergence here is a **consensus** bug, not a slow path, so
//! they are not cfg-gated: they compile for the host too and
//! `crates/emulator/tests/revm.rs` holds them against the real
//! `DefaultCrypto` over a corpus that includes the malformed inputs a block
//! never supplies.

use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use revm::precompile::PrecompileHalt;

/// A field element's width, in bytes.
const FQ_LEN: usize = 32;
/// An encoded G1 point's width: `x ‖ y`, each big-endian.
const G1_LEN: usize = 2 * FQ_LEN;
/// A scalar's width, in bytes.
const SCALAR_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Parsing and encoding: upstream's, mirrored
// ---------------------------------------------------------------------------

/// One `Fq` from thirty-two big-endian bytes, refusing a non-member.
fn read_fq(input_be: &[u8; FQ_LEN]) -> Result<Fq, PrecompileHalt> {
    let mut input_le = *input_be;
    input_le.reverse();
    Fq::deserialize_uncompressed(&input_le[..])
        .map_err(|_| PrecompileHalt::Bn254FieldPointNotAMember)
}

/// A G1 point from its two coordinates.
///
/// `(0, 0)` is the encoding of the point at infinity and is **not** a curve
/// point, which is why it is answered before the curve check rather than by it.
fn new_g1_point(px: Fq, py: Fq) -> Result<G1Affine, PrecompileHalt> {
    if px.is_zero() && py.is_zero() {
        Ok(G1Affine::zero())
    } else {
        let point = G1Affine::new_unchecked(px, py);
        if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
        }
        Ok(point)
    }
}

/// A G1 point from sixty-four big-endian bytes.
///
/// # Panics
///
/// If `input` is shorter than sixty-four bytes, as upstream's does. Every
/// caller right-pads first.
pub fn read_g1_point(input: &[u8]) -> Result<G1Affine, PrecompileHalt> {
    let input: &[u8; G1_LEN] = input[..G1_LEN]
        .try_into()
        .expect("input must be at least G1_LEN bytes");
    let (px, py) = input.split_at(FQ_LEN);
    let px = read_fq(px.try_into().expect("split must yield FQ_LEN bytes"))?;
    let py = read_fq(py.try_into().expect("split must yield FQ_LEN bytes"))?;
    new_g1_point(px, py)
}

/// A G1 point as sixty-four big-endian bytes; all zero at infinity.
pub fn encode_g1_point(point: G1Affine) -> [u8; G1_LEN] {
    let mut output = [0u8; G1_LEN];
    let Some((x, y)) = point.xy() else {
        return output;
    };
    let mut x_bytes = [0u8; FQ_LEN];
    x.serialize_uncompressed(&mut x_bytes[..])
        .expect("an Fq serializes into FQ_LEN bytes");
    let mut y_bytes = [0u8; FQ_LEN];
    y.serialize_uncompressed(&mut y_bytes[..])
        .expect("an Fq serializes into FQ_LEN bytes");
    x_bytes.reverse();
    y_bytes.reverse();
    output[0..FQ_LEN].copy_from_slice(&x_bytes);
    output[FQ_LEN..G1_LEN].copy_from_slice(&y_bytes);
    output
}

/// A scalar from thirty-two big-endian bytes, reduced.
fn read_scalar(input: &[u8]) -> Fr {
    let input: &[u8; SCALAR_LEN] = input.try_into().expect("input must be SCALAR_LEN bytes");
    Fr::from_be_bytes_mod_order(input)
}

// ---------------------------------------------------------------------------
// The two group operations
// ---------------------------------------------------------------------------

/// `p1 + p2` over the precompile's byte boundary: `0x06`.
pub fn g1_add(p1_bytes: &[u8], p2_bytes: &[u8]) -> Result<[u8; G1_LEN], PrecompileHalt> {
    let p1 = read_g1_point(p1_bytes)?;
    let p2 = read_g1_point(p2_bytes)?;
    #[cfg(target_arch = "riscv32")]
    let sum = delegated::add_affine(&p1, &p2);
    #[cfg(not(target_arch = "riscv32"))]
    let sum = G1Projective::from(p1) + p2;
    Ok(encode_g1_point(sum.into_affine()))
}

/// `scalar · point` over the precompile's byte boundary: `0x07`.
pub fn g1_mul(point_bytes: &[u8], fr_bytes: &[u8]) -> Result<[u8; G1_LEN], PrecompileHalt> {
    let p = read_g1_point(point_bytes)?;
    let fr = read_scalar(fr_bytes);
    #[cfg(target_arch = "riscv32")]
    let product = delegated::mul_affine(&p, &fr);
    #[cfg(not(target_arch = "riscv32"))]
    let product = p.mul_bigint(fr.into_bigint());
    Ok(encode_g1_point(product.into_affine()))
}

// ---------------------------------------------------------------------------
// The delegated arithmetic
// ---------------------------------------------------------------------------

#[cfg(target_arch = "riscv32")]
mod delegated {
    use super::{AffineRepr, Fq, Fr, G1Affine, G1Projective, PrimeField};
    use guest_sdk::recursion::{ec_add_complete, EcAddFrame, BN254_GROUPS};

    /// A point in **homogeneous** projective coordinates — `x = X/Z`,
    /// `y = Y/Z` — which is the delegation's representation and **not**
    /// arkworks', whose `Projective` is Jacobian.
    type Homogeneous = [[u32; 8]; 3];

    /// A field element's eight little-endian 32-bit limbs. arkworks holds
    /// `x·R`; `into_bigint` is the conversion out of Montgomery form, so what
    /// this returns is the canonical integer the frame requires — below `q` by
    /// the type's own invariant, so the operand bound costs nothing here.
    fn limbs(f: &Fq) -> [u32; 8] {
        let w = f.into_bigint().0;
        core::array::from_fn(|k| (w[k / 2] >> (32 * (k % 2))) as u32)
    }

    /// [`limbs`]' inverse. Every lane the delegation writes is below `q`, so
    /// the reduction `from_le_bytes_mod_order` performs is the identity.
    fn field(v: &[u32; 8]) -> Fq {
        let mut bytes = [0u8; 32];
        for (k, limb) in v.iter().enumerate() {
            bytes[4 * k..4 * k + 4].copy_from_slice(&limb.to_le_bytes());
        }
        Fq::from_le_bytes_mod_order(&bytes)
    }

    /// The homogeneous identity, `(0 : 1 : 0)`.
    fn identity() -> Homogeneous {
        let mut one = [0u32; 8];
        one[0] = 1;
        [[0u32; 8], one, [0u32; 8]]
    }

    /// An affine point lifted to `Z = 1`; the identity lifted to `(0 : 1 : 0)`.
    ///
    /// The special case is required and not defensive: arkworks encodes an
    /// affine infinity as `(0, 0)` with a flag, and `(0 : 0 : 1)` is neither
    /// the projective identity nor a curve point, so no complete formula
    /// rescues it.
    fn lift(p: &G1Affine) -> Homogeneous {
        if p.is_zero() {
            return identity();
        }
        let mut one = [0u32; 8];
        one[0] = 1;
        [limbs(&p.x), limbs(&p.y), one]
    }

    /// `a + b`, as three `EC_ADD` invocations.
    ///
    /// `false` from the shim is exactly `-ENOSYS` — an executor with no
    /// `EC_ADD` circuit — and then the answer comes from arkworks, through the
    /// Jacobian conversion below. The two paths agree as points; they do not
    /// agree as representatives, and nothing here compares representatives.
    fn add(a: &Homogeneous, b: &Homogeneous) -> Homogeneous {
        let mut frame = EcAddFrame::of(&BN254_GROUPS, a, b);
        if ec_add_complete(&mut frame, &BN254_GROUPS) {
            return frame.result();
        }
        homogeneous(&(jacobian(a) + jacobian(b)))
    }

    /// A homogeneous point as arkworks' Jacobian one: `(X·Z, Y·Z², Z)`, since
    /// arkworks reads `x = X/Z²` and `y = Y/Z³` where this reads `x = X/Z`.
    fn jacobian(p: &Homogeneous) -> G1Projective {
        let (x, y, z) = (field(&p[0]), field(&p[1]), field(&p[2]));
        let zz = z * z;
        G1Projective::new_unchecked(x * z, y * zz, z)
    }

    /// arkworks' Jacobian point as a homogeneous one: `(X·Z, Y, Z³)`, since
    /// `X/Z² = (X·Z)/Z³` and `Y/Z³ = Y/Z³`.
    fn homogeneous(p: &G1Projective) -> Homogeneous {
        let zz = p.z * p.z;
        [limbs(&(p.x * p.z)), limbs(&p.y), limbs(&(zz * p.z))]
    }

    /// `a + b` for two affine points, as an arkworks Jacobian point.
    pub(super) fn add_affine(a: &G1Affine, b: &G1Affine) -> G1Projective {
        jacobian(&add(&lift(a), &lift(b)))
    }

    /// `k · p`, by double-and-add from the top bit.
    ///
    /// Completeness is what makes this five lines: the accumulator starts at
    /// the identity, every doubling is `P + P`, and no step has a case to
    /// branch on — not the first iteration, not a bit that repeats a point, not
    /// the identity itself. A ladder over an incomplete formula needs all
    /// three, and each is a place to be wrong only on inputs a test does not
    /// reach.
    pub(super) fn mul_affine(p: &G1Affine, k: &Fr) -> G1Projective {
        let base = lift(p);
        let mut acc = identity();
        let words = k.into_bigint().0;
        let mut bit = 64 * words.len();
        while bit > 0 {
            bit -= 1;
            acc = add(&acc, &acc);
            if (words[bit / 64] >> (bit % 64)) & 1 == 1 {
                acc = add(&acc, &base);
            }
        }
        jacobian(&acc)
    }
}

// ---------------------------------------------------------------------------
// The provider
// ---------------------------------------------------------------------------

/// The `Crypto` provider this image installs: three methods of the trait's
/// eighteen, and the other fifteen left at their upstream bodies.
#[cfg(target_arch = "riscv32")]
#[derive(Clone, Copy, Debug, Default)]
pub struct ApogeeCrypto;

#[cfg(target_arch = "riscv32")]
impl revm::precompile::Crypto for ApogeeCrypto {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        guest_sdk::sha256(input)
    }

    fn bn254_g1_add(&self, p1: &[u8], p2: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        g1_add(p1, p2)
    }

    fn bn254_g1_mul(&self, point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        g1_mul(point, scalar)
    }
}

/// Install [`ApogeeCrypto`], on the guest target and nowhere else.
///
/// **Order is load-bearing.** revm's provider is a `OnceLock` read through
/// `get_or_init`, so the *first* read installs `DefaultCrypto` permanently if
/// nothing has been installed by then. This therefore runs before the EVM is
/// built, and `install_crypto`'s `false` — "already set" — is the ordinary
/// answer on every call after the first and is not an error.
///
/// On the host this is a no-op and no provider is installed at all, so the
/// native-revm oracle runs upstream's software for all eighteen methods.
pub fn install() {
    #[cfg(target_arch = "riscv32")]
    {
        let _ = revm::install_crypto(ApogeeCrypto);
    }
}
