#![no_std]
//! The Poseidon2 duplex transcript over the A64-C5 field, specified in
//! `docs/spec/transcript.md`:
//!
//! - the field `p = 2^64 − 59` and the Poseidon2-A64-C5 permutation (§1);
//! - Chiesa–Orrù's overwrite duplex, rate 8 and capacity 8, keyed by
//!   [`PROTOCOL_ID`] (§2);
//! - the typed messages, challenges, digests, snapshots and event log (§3).
//!
//! `#![no_std]`: guests and the no_std verifier core link it.

extern crate alloc;

use alloc::vec::Vec;
use core::ops::{Add, Mul};

mod params;

// ---------------------------------------------------------------------------
// The field (§1.1).
// ---------------------------------------------------------------------------

/// The A64-C5 prime, `2^64 − 59`.
pub const A64_C5: u64 = 0xFFFF_FFFF_FFFF_FFC5;

const P: u128 = A64_C5 as u128;

/// An element of the A64-C5 field, held as its canonical representative.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Fp(u64);

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);

    /// `x mod p`. A `u64` is below `2p`, so `p` is subtracted at most once.
    pub const fn from_u64(x: u64) -> Fp {
        Fp(if x >= A64_C5 { x - A64_C5 } else { x })
    }

    /// `x`, if it is canonical.
    pub const fn from_canonical(x: u64) -> Option<Fp> {
        if x < A64_C5 {
            Some(Fp(x))
        } else {
            None
        }
    }

    /// The canonical representative, in `[0, p)`.
    pub const fn to_u64(self) -> u64 {
        self.0
    }

    /// `x mod p` for any `x < 2^128`. Two folds by `2^64 ≡ 59` leave
    /// `x < 2^64 + 3481 < 2p`, so `p` is then subtracted at most once.
    fn reduce(x: u128) -> Fp {
        let x = (x >> 64) * 59 + (x as u64 as u128);
        let x = (x >> 64) * 59 + (x as u64 as u128);
        Fp((if x >= P { x - P } else { x }) as u64)
    }
}

impl Add for Fp {
    type Output = Fp;

    fn add(self, rhs: Fp) -> Fp {
        let s = self.0 as u128 + rhs.0 as u128;
        Fp((if s >= P { s - P } else { s }) as u64)
    }
}

impl Mul for Fp {
    type Output = Fp;

    fn mul(self, rhs: Fp) -> Fp {
        Fp::reduce(self.0 as u128 * rhs.0 as u128)
    }
}

// ---------------------------------------------------------------------------
// Poseidon2-A64-C5 (§1.2): width 16, `x^3`, 6 full rounds, 42 partial rounds,
// 6 full rounds.
// ---------------------------------------------------------------------------

/// The permutation's width.
pub const WIDTH: usize = 16;

/// The sponge's rate: lanes `0..RATE` are absorbed into and squeezed from,
/// lanes `RATE..WIDTH` are the capacity.
pub const RATE: usize = 8;

/// HorizenLabs' `M4`, MDS over `p`: every minor is a nonzero integer of
/// magnitude at most 64.
const M4: [[u128; 4]; 4] = [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]];

/// `x^3`, a permutation of the field because `3 ∤ p − 1`.
fn sbox(x: Fp) -> Fp {
    x * x * x
}

/// The external layer `circ(2·M4, M4, M4, M4)`: block `b` becomes
/// `M4·s_b + Σ_j M4·s_j`. An entry of `y` is below `16p` and one of `sum` below
/// `64p`, so each lane is reduced once.
fn external(s: &mut [Fp; WIDTH]) {
    let y: [[u128; 4]; 4] = core::array::from_fn(|b| {
        core::array::from_fn(|r| (0..4).map(|c| M4[r][c] * s[4 * b + c].0 as u128).sum())
    });
    let sum: [u128; 4] = core::array::from_fn(|r| y.iter().map(|block| block[r]).sum());
    for (i, x) in s.iter_mut().enumerate() {
        *x = Fp::reduce(y[i / 4][i % 4] + sum[i % 4]);
    }
}

/// The internal layer `M_I = J + diag(μ − 1)`: lane `i` becomes
/// `(μ_i − 1)·s_i + Σ_j s_j`, below `p² + 16p < 2^128`.
fn internal(s: &mut [Fp; WIDTH]) {
    let sum: u128 = s.iter().map(|x| x.0 as u128).sum();
    for (x, &d) in s.iter_mut().zip(&params::INTERNAL_DIAG_M_1) {
        *x = Fp::reduce(d as u128 * x.0 as u128 + sum);
    }
}

/// A round constant into every lane, the S-box on every lane, then `M_E`.
fn full_round(s: &mut [Fp; WIDTH], rc: &[u64; WIDTH]) {
    for (x, &c) in s.iter_mut().zip(rc) {
        *x = sbox(*x + Fp(c));
    }
    external(s);
}

/// The Poseidon2-A64-C5 permutation, in place.
pub fn poseidon2_permute(state: &mut [Fp; WIDTH]) {
    external(state);
    for rc in &params::RC_INITIAL {
        full_round(state, rc);
    }
    for &rc in &params::RC_PARTIAL {
        state[0] = sbox(state[0] + Fp(rc));
        internal(state);
    }
    for rc in &params::RC_TERMINAL {
        full_round(state, rc);
    }
}

// ---------------------------------------------------------------------------
// The duplex sponge (§2) and its typed messages (§3).
// ---------------------------------------------------------------------------

/// The protocol identifier, packed seven bytes to a lane into the capacity of
/// every fresh sponge. It changes whenever this construction does.
pub const PROTOCOL_ID: &[u8] = b"apogee-vm/transcript-a64-c5/v1";

const _: () = assert!(PROTOCOL_ID.len() <= 7 * (WIDTH - RATE));

/// A domain-separation tag. Values live only in `constants::transcript_tags`.
pub type Tag = u64;

/// One element of the quadratic extension `F_{p^2}`: its two coordinates, in
/// the order they leave the rate.
pub type Challenge = [Fp; 2];

/// A digest: the whole rate after the last message.
pub type Digest = [Fp; RATE];

/// Up to seven bytes, little-endian: below `2^56 < p`, so one canonical lane.
fn lane(bytes: &[u8]) -> Fp {
    debug_assert!(bytes.len() <= 7);
    let mut le = [0u8; 8];
    le[..bytes.len()].copy_from_slice(bytes);
    Fp(u64::from_le_bytes(le))
}

/// A record of one typed operation. Metadata only: the log never feeds the
/// sponge, and a snapshot does not carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptEvent {
    /// A message under `tag` with `n` payload lanes: its scalars, or its
    /// 7-byte chunks. The frame's two lanes are not counted.
    Absorb { tag: Tag, n: usize },
    /// A challenge drawn under `tag`.
    Challenge { tag: Tag },
}

/// A transcript's sponge state and duplex positions: exactly what resumes its
/// stream. A deterministic function of the operations that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptSnapshot {
    state: [Fp; WIDTH],
    absorbed: u8,
    squeezed: u8,
}

/// The Poseidon2-A64-C5 duplex transcript.
pub struct Transcript {
    state: [Fp; WIDTH],
    /// Rate lanes written since the last permutation or squeeze.
    absorbed: usize,
    /// Rate lanes read since the last permutation; `RATE` when none is left.
    squeezed: usize,
    events: Vec<TranscriptEvent>,
}

// A `Default` impl would be a second name for `new` with no caller; the lint
// has nothing to catch here.
#[allow(clippy::new_without_default)]
impl Transcript {
    /// A fresh sponge: the rate zero, [`PROTOCOL_ID`] in the capacity.
    pub fn new() -> Transcript {
        let mut state = [Fp::ZERO; WIDTH];
        for (x, chunk) in state[RATE..].iter_mut().zip(PROTOCOL_ID.chunks(7)) {
            *x = lane(chunk);
        }
        Transcript {
            state,
            absorbed: 0,
            squeezed: RATE,
            events: Vec::new(),
        }
    }

    /// Overwrite the next rate lane, permuting first when the rate is full.
    fn absorb(&mut self, x: Fp) {
        if self.absorbed == RATE {
            poseidon2_permute(&mut self.state);
            self.absorbed = 0;
        }
        self.state[self.absorbed] = x;
        self.absorbed += 1;
        self.squeezed = RATE;
    }

    /// Read the next rate lane, permuting first when none is left: the first
    /// squeeze after an absorb always comes from a fresh permutation.
    fn squeeze(&mut self) -> Fp {
        if self.squeezed == RATE {
            poseidon2_permute(&mut self.state);
            self.squeezed = 0;
        }
        self.absorbed = 0;
        self.squeezed += 1;
        self.state[self.squeezed - 1]
    }

    /// The two lanes every message opens with. A tag is a small constant and a
    /// length is below `2^63`, so each is one canonical lane.
    fn frame(&mut self, tag: Tag, n: usize) {
        self.absorb(Fp::from_u64(tag));
        self.absorb(Fp::from_u64(n as u64));
    }

    /// Absorb one scalar under `tag`. Exactly `append_scalars(tag, &[x])`.
    pub fn append_scalar(&mut self, tag: Tag, x: Fp) {
        self.append_scalars(tag, &[x]);
    }

    /// Absorb `tag`, the scalar count, then the scalars.
    pub fn append_scalars(&mut self, tag: Tag, xs: &[Fp]) {
        self.frame(tag, xs.len());
        for &x in xs {
            self.absorb(x);
        }
        self.events
            .push(TranscriptEvent::Absorb { tag, n: xs.len() });
    }

    /// Absorb `tag`, the byte length, then the bytes in 7-byte little-endian
    /// lanes, the last zero-padded. The byte length, not the lane count, keeps
    /// `"abc"` and `"abc\0"` apart.
    pub fn append_bytes(&mut self, tag: Tag, bytes: &[u8]) {
        self.frame(tag, bytes.len());
        for chunk in bytes.chunks(7) {
            self.absorb(lane(chunk));
        }
        self.events.push(TranscriptEvent::Absorb {
            tag,
            n: bytes.len().div_ceil(7),
        });
    }

    /// Absorb `tag` and draw one challenge in `F_{p^2}`: two lanes of a fresh
    /// permutation.
    pub fn challenge(&mut self, tag: Tag) -> Challenge {
        self.absorb(Fp::from_u64(tag));
        let c = [self.squeeze(), self.squeeze()];
        self.events.push(TranscriptEvent::Challenge { tag });
        c
    }

    /// End a digest sponge: the eight rate lanes of one more permutation.
    pub fn digest(mut self) -> Digest {
        core::array::from_fn(|_| self.squeeze())
    }

    /// Capture the sponge state and both positions.
    pub fn snapshot(&self) -> TranscriptSnapshot {
        TranscriptSnapshot {
            state: self.state,
            absorbed: self.absorbed as u8,
            squeezed: self.squeezed as u8,
        }
    }

    /// Resume a transcript from a snapshot, with an empty event log.
    pub fn restore(s: &TranscriptSnapshot) -> Transcript {
        Transcript {
            state: s.state,
            absorbed: s.absorbed as usize,
            squeezed: s.squeezed as usize,
            events: Vec::new(),
        }
    }

    /// Every typed operation this transcript has performed, in order.
    pub fn event_log(&self) -> &[TranscriptEvent] {
        &self.events
    }
}

// ---------------------------------------------------------------------------
// Snapshot serde (§3): `(lanes, absorbed, squeezed)`, each lane canonical.
// ---------------------------------------------------------------------------

impl serde::Serialize for TranscriptSnapshot {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.state.map(Fp::to_u64), self.absorbed, self.squeezed).serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for TranscriptSnapshot {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<TranscriptSnapshot, D::Error> {
        use serde::de::Error;
        let (lanes, absorbed, squeezed) = <([u64; WIDTH], u8, u8)>::deserialize(d)?;
        let malformed = || D::Error::custom("malformed transcript snapshot");

        // Refuse what `snapshot` cannot produce: a lane at or above `p`, or
        // positions no operation sequence reaches. A squeeze leaves
        // `squeezed ≥ 1` and `absorbed = 0`; an absorb leaves `squeezed = RATE`.
        let (a, q) = (absorbed as usize, squeezed as usize);
        if a > RATE || !(1..=RATE).contains(&q) || (a > 0 && q < RATE) {
            return Err(malformed());
        }
        let mut state = [Fp::ZERO; WIDTH];
        for (x, &v) in state.iter_mut().zip(&lanes) {
            *x = Fp::from_canonical(v).ok_or_else(malformed)?;
        }
        Ok(TranscriptSnapshot {
            state,
            absorbed,
            squeezed,
        })
    }
}

// ---------------------------------------------------------------------------
// The public I/O digest.
// ---------------------------------------------------------------------------

/// The digest that binds a statement's public input and public output,
/// `docs/spec/public-values.md` §5: two typed byte messages in a sponge of
/// their own, then [`Transcript::digest`].
pub fn io_digest(public_input: &[u8], public_output: &[u8]) -> Digest {
    let mut t = Transcript::new();
    t.append_bytes(
        constants::transcript_tags::PUBLIC_INPUT_STREAM,
        public_input,
    );
    t.append_bytes(
        constants::transcript_tags::PUBLIC_OUTPUT_STREAM,
        public_output,
    );
    t.digest()
}
