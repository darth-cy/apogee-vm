#![no_std]
//! The verifier half of Akita, the lattice polynomial commitment scheme of
//! Dao, Bodaghi, Khajehpour, Vitto, Badakhshan, Georghiades, Liu, Zhang and
//! Thaler (ePrint 2026/1983), over A64-C5 with evaluations in `F_{p^2}`.
//! `docs/spec/pcs.md` specifies it; section and equation numbers in the code
//! are the paper's.
//!
//! - [`ring`]: `R_d = F_q[X]/(X^d + 1)`, digits, the field embedding, trace
//!   packing;
//! - [`sample`]: lane streams, the public setup, folding challenges;
//! - [`params`]: schedules, from the shape of what is opened;
//! - [`relation`]: a fold's witness layout and its quotient-lifted rows;
//! - [`proof`]: the messages;
//! - [`verify`]: the verifier.
//!
//! `#![no_std]` + `alloc`. `crates/pcs` is the prover half and re-exports
//! everything here.

extern crate alloc;

pub mod params;
pub mod proof;
pub mod relation;
pub mod ring;
pub mod sample;
mod table;
pub mod verify;

pub use params::Schedule;
pub use proof::{Commitment, Proof};
pub use sample::Setup;
pub use verify::{setup_need, verify, Error};
