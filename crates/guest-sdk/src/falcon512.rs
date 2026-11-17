//! Falcon-512's lattice check by the precompile
//! (`constants::delegation::falcon`, `docs/spec/precompiles.md`).

use constants::delegation::falcon::{C, FRAME, H, N, NORM_HI, NORM_LO, S2};

/// A polynomial of `Z_q[x]/(x^512 + 1)`, `q = 12289`: coefficient `i` at
/// `self.0[i]`, read mod `q` by [`s1_norm`], so any 512 `u16` are one.
/// Word-aligned, as the call reads an array a word at a time: coefficient `2i`
/// is word `i`'s low halfword and `2i + 1` its high one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct Poly(pub [u16; N]);

/// `‖s1‖²` by the precompile, `s1 = (c − s2·h) mod (q, x^512 + 1)` with each
/// coefficient centered to `[−6144, 6144]`: Falcon-512 verification's lattice
/// check, which accepts the signature `s2` of the hashed message `c` under
/// the public key `h` when this and `‖s2‖²` sum to at most `⌊β²⌋`. Below
/// `2^35`.
///
/// The three are read in place, anywhere a load reaches, the advice included.
/// Panics unless they are apart: the call reads every word of them at once.
pub fn s1_norm(h: &Poly, s2: &Poly, c: &Poly) -> u64 {
    // SAFETY: each borrow is 512 `u16`, word-aligned.
    unsafe { s1_norm_at(h.0.as_ptr(), s2.0.as_ptr(), c.0.as_ptr()) }
}

/// [`s1_norm`] over the 512 coefficients at each of `h`, `s2` and `c`. Panics
/// unless each is word-aligned and the three are apart.
///
/// # Safety
/// `h`, `s2` and `c` are each valid for reads of 512 `u16`.
pub(crate) unsafe fn s1_norm_at(h: *const u16, s2: *const u16, c: *const u16) -> u64 {
    let at = [h, s2, c].map(|p| p as usize);
    let apart = |i: usize, j: usize| at[i].abs_diff(at[j]) >= 2 * N;
    assert!(
        at.iter().all(|a| a.is_multiple_of(4)) && apart(0, 1) && apart(0, 2) && apart(1, 2),
        "falcon512::s1_norm: three word-aligned arrays, apart"
    );
    let mut frame = [0u32; FRAME];
    frame[H] = at[0] as u32;
    frame[S2] = at[1] as u32;
    frame[C] = at[2] as u32;
    // SAFETY: the frame is five words on the stack, below the advice region
    // and apart from the arrays, each readable for 1,024 bytes.
    super::delegate(&super::FALCON512, frame.as_mut_ptr());
    frame[NORM_LO] as u64 | (frame[NORM_HI] as u64) << 32
}
