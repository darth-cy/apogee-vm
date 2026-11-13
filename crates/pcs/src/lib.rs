//! The prover half of Akita: commitments and openings. `docs/spec/pcs.md`
//! specifies it; `crates/pcs-verify` is the verifier half, re-exported here.

pub mod commit;
mod ntt;
mod prove;
mod sumcheck;

pub use commit::{commit, Opener, Source};
pub use pcs_verify::*;
pub use prove::open;

use rayon::prelude::*;

/// [`Setup::expand`] on every core: the same coefficients, block-parallel.
pub fn expand_setup(len: usize) -> Setup {
    let blocks = len.div_ceil(transcript::RATE) as u64;
    let mut v: Vec<field::Fp> = (0..blocks)
        .into_par_iter()
        .flat_map_iter(sample::setup_block)
        .collect();
    v.truncate(len);
    Setup(v)
}
