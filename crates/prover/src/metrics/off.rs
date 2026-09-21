//! The metrics seam with the feature **off**: the whole harness as zero-sized
//! types and empty bodies.
//!
//! This is the build everything but `--features metrics` gets, and it is the
//! build every proof in this repository is made in. `Recorder` and `Span` are
//! zero-sized, so passing one is not a pass at all; every method is an empty
//! `#[inline(always)]` body, so a call emits no code; and `start` **does not
//! read the clock**, which is the point — a timing seam that sampled the clock
//! in the default build would be a metrics harness nobody asked for.
//!
//! Only the methods the prover calls *outside* a `metric!` block exist here.
//! Everything inside one — every byte count, every shape note — needs no
//! counterpart, because `metric!` expands to nothing with the feature off and
//! its arguments are never evaluated (`super`'s module docs).

use super::{ShardId, Stage};

/// An open span, with the feature off: nothing, and no clock was read to make
/// it.
#[derive(Clone, Copy, Debug)]
pub struct Span;

/// The collector, with the feature off: nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Recorder;

impl Recorder {
    #[inline(always)]
    pub fn new() -> Recorder {
        Recorder
    }

    /// One rayon task's own recorder. With the feature off there is nothing to
    /// keep apart, so this is `new`.
    #[inline(always)]
    pub fn for_shard(_shard: ShardId) -> Recorder {
        Recorder
    }

    #[inline(always)]
    pub fn start(&self, _stage: Stage) -> Span {
        Span
    }

    #[inline(always)]
    pub fn end(&mut self, _span: Span) {}

    /// Merge a task's recorder into this one.
    #[inline(always)]
    pub fn absorb(&mut self, _other: Recorder) {}
}
