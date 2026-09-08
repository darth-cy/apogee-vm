//! What every routine shares: the seed, the repetition count, and the two ways
//! of taking a best-of-N measurement.

use std::time::{Duration, Instant};

use test_support::Rng;

/// Best of this many runs, to blunt scheduler noise.
pub const REPS: usize = 3;

/// The one seed. Every routine derives its own stream from it, so a routine
/// run alone sees exactly the data it sees when run with the others.
pub const SEED: u64 = 20260903;

/// The smallest of the durations folded into it. `Duration::MAX` until the
/// first `record`, which no routine prints because every routine records at
/// least once.
pub struct Best(Duration);

impl Best {
    pub fn new() -> Best {
        Best(Duration::MAX)
    }

    pub fn record(&mut self, d: Duration) {
        self.0 = self.0.min(d);
    }

    pub fn get(&self) -> Duration {
        self.0
    }
}

/// Best of [`REPS`] runs of `f`. For a measurement that needs per-run setup
/// left out of the timed region, time the region by hand and fold with
/// [`Best`] instead.
pub fn best<F: FnMut()>(mut f: F) -> Duration {
    let mut best = Best::new();
    for _ in 0..REPS {
        let t = Instant::now();
        f();
        best.record(t.elapsed());
    }
    best.get()
}

pub fn ns_per_op(d: Duration, ops: usize) -> f64 {
    d.as_secs_f64() * 1e9 / ops as f64
}

pub fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

/// Canonical bytes of a nonzero element, so two libraries handed the same
/// stream get the same values. Nonzero because an inversion benchmark must not
/// measure the zero path.
pub fn next_canonical(rng: &mut Rng) -> [u8; 32] {
    loop {
        let mut b = rng.next_le32();
        b[31] &= 0x3f; // p < 2^254, so clearing two bits keeps rejection rare
        match field::Fr::from_bytes(&b) {
            Some(x) if x != field::Fr::ZERO => return b,
            _ => continue,
        }
    }
}
