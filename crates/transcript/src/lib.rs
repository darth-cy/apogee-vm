#![no_std]
//! The Poseidon2 duplex transcript over the A64-C5 field, specified in
//! `docs/spec/transcript.md`:
//!
//! - the Poseidon2-A64-C5 permutation (§1);
//! - Chiesa–Orrù's overwrite duplex, rate 8 and capacity 8, keyed by
//!   [`PROTOCOL_ID`] (§2);
//! - the typed messages, challenges, digests, snapshots and event log (§3).
//!
//! `#![no_std]`: guests and the no_std verifier core link it.

extern crate alloc;

use alloc::vec::Vec;
use field::{Fp, Fp2};

mod params;

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
    let v = s.map(Fp::to_u64);
    let y: [[u128; 4]; 4] = core::array::from_fn(|b| {
        core::array::from_fn(|r| (0..4).map(|c| M4[r][c] * v[4 * b + c] as u128).sum())
    });
    let sum: [u128; 4] = core::array::from_fn(|r| y.iter().map(|block| block[r]).sum());
    for (i, x) in s.iter_mut().enumerate() {
        *x = Fp::from_u128(y[i / 4][i % 4] + sum[i % 4]);
    }
}

/// The internal layer `M_I = J + diag(μ − 1)`: lane `i` becomes
/// `(μ_i − 1)·s_i + Σ_j s_j`, below `p² + 16p < 2^128`.
fn internal(s: &mut [Fp; WIDTH]) {
    let sum: u128 = s.iter().map(|x| x.to_u64() as u128).sum();
    for (x, &d) in s.iter_mut().zip(&params::INTERNAL_DIAG_M_1) {
        *x = Fp::from_u128(d as u128 * x.to_u64() as u128 + sum);
    }
}

// The round constants of `params` as field elements, converted at compile time
// so that no round pays for the conversion.
const RC_INITIAL: [[Fp; WIDTH]; 6] = rows(params::RC_INITIAL);
const RC_PARTIAL: [Fp; 42] = lanes(params::RC_PARTIAL);
const RC_TERMINAL: [[Fp; WIDTH]; 6] = rows(params::RC_TERMINAL);

const fn lanes<const N: usize>(xs: [u64; N]) -> [Fp; N] {
    let mut out = [Fp::ZERO; N];
    let mut i = 0;
    while i < N {
        out[i] = Fp::from_u64(xs[i]);
        i += 1;
    }
    out
}

const fn rows<const R: usize>(xs: [[u64; WIDTH]; R]) -> [[Fp; WIDTH]; R] {
    let mut out = [[Fp::ZERO; WIDTH]; R];
    let mut i = 0;
    while i < R {
        out[i] = lanes(xs[i]);
        i += 1;
    }
    out
}

/// A round constant into every lane, the S-box on every lane, then `M_E`.
fn full_round(s: &mut [Fp; WIDTH], rc: &[Fp; WIDTH]) {
    for (x, &c) in s.iter_mut().zip(rc) {
        *x = sbox(*x + c);
    }
    external(s);
}

/// The Poseidon2-A64-C5 permutation, in place.
pub fn poseidon2_permute(state: &mut [Fp; WIDTH]) {
    external(state);
    for rc in &RC_INITIAL {
        full_round(state, rc);
    }
    for &rc in &RC_PARTIAL {
        state[0] = sbox(state[0] + rc);
        internal(state);
    }
    for rc in &RC_TERMINAL {
        full_round(state, rc);
    }
}

// ---------------------------------------------------------------------------
// The duplex sponge (§2) and its typed messages (§3).
// ---------------------------------------------------------------------------

/// The protocol identifier, packed seven bytes to a lane into the capacity of
/// every fresh sponge. It names the construction, not the crate, and changes
/// whenever the construction does.
pub const PROTOCOL_ID: &[u8] = b"apogee-vm/transcript-a64-c5/v1";

const _: () = assert!(PROTOCOL_ID.len() <= 7 * (WIDTH - RATE));

/// A domain-separation tag. Values live only in `constants::transcript_tags`.
pub type Tag = u64;

/// A digest: the whole rate after the last message.
pub type Digest = [Fp; RATE];

/// Up to seven bytes, little-endian: below `2^56 < p`, so one canonical lane.
fn lane(bytes: &[u8]) -> Fp {
    debug_assert!(bytes.len() <= 7);
    let mut le = [0u8; 8];
    le[..bytes.len()].copy_from_slice(bytes);
    Fp::from_u64(u64::from_le_bytes(le))
}

/// A record of one typed operation. Metadata only: the log never feeds the
/// sponge, and a snapshot does not carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptEvent {
    /// A message under `tag` with `n` payload lanes: its scalars, two per
    /// `F_{p^2}` element, or its 7-byte chunks. The frame's two lanes are not
    /// counted.
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

    /// Absorb `F_{p^2}` elements under `tag`: exactly `append_scalars` of their
    /// coordinates, `c0` then `c1` of each.
    pub fn append_ext(&mut self, tag: Tag, xs: &[Fp2]) {
        self.frame(tag, 2 * xs.len());
        for x in xs {
            self.absorb(x.c0);
            self.absorb(x.c1);
        }
        self.events.push(TranscriptEvent::Absorb {
            tag,
            n: 2 * xs.len(),
        });
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
    /// permutation, `c0` then `c1`.
    pub fn challenge(&mut self, tag: Tag) -> Fp2 {
        self.absorb(Fp::from_u64(tag));
        let c = Fp2 {
            c0: self.squeeze(),
            c1: self.squeeze(),
        };
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
// Snapshot serde (§3): `(lanes, absorbed, squeezed)`, each lane `Fp`'s 8
// canonical bytes, so a snapshot is a fixed 130 bytes under postcard.
// ---------------------------------------------------------------------------

impl serde::Serialize for TranscriptSnapshot {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.state, self.absorbed, self.squeezed).serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for TranscriptSnapshot {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<TranscriptSnapshot, D::Error> {
        use serde::de::Error;
        // A lane at or above `p` is refused by `Fp`'s own decoding.
        let (state, absorbed, squeezed) = <([Fp; WIDTH], u8, u8)>::deserialize(d)?;

        // Refuse positions no operation sequence reaches. A squeeze leaves
        // `squeezed ≥ 1` and `absorbed = 0`; an absorb leaves `squeezed = RATE`.
        let (a, q) = (absorbed as usize, squeezed as usize);
        if a > RATE || !(1..=RATE).contains(&q) || (a > 0 && q < RATE) {
            return Err(D::Error::custom("malformed transcript snapshot"));
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
