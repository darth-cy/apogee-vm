#![no_std]
//! The Poseidon2 duplex transcript: every challenge in the protocol comes from
//! here.
//!
//! Two layers, specified in `docs/spec/transcript.md`:
//!
//! - the **raw duplex** — [`Transcript::observe`] and [`Transcript::sample`] —
//!   which is the Plonky3 `DuplexChallenger` over the width-3 BN254 Poseidon2
//!   permutation, rate 2, capacity 1, overwrite absorption, zero-padded and
//!   length-tagged absorbs, and challenges popped from the end of the rate;
//! - the **typed layer** — [`Transcript::append_scalar`],
//!   [`Transcript::append_scalars`], [`Transcript::append_bytes`],
//!   [`Transcript::challenge_scalar`] — which frames every message as
//!   `tag, length, payload...` over that duplex.
//!
//! `#![no_std]`: the recursion guest verifies base proofs on this VM and draws
//! its randomness through this same API.

extern crate alloc;

use alloc::vec::Vec;

use constants::{POSEIDON2_RC3_INITIAL, POSEIDON2_RC3_INTERNAL, POSEIDON2_RC3_TERMINAL};
use field::Fr;

// ---------------------------------------------------------------------------
// Poseidon2, width 3, over the BN254 scalar field.
//
// 8 full rounds (4 initial, 4 terminal) around 56 partial rounds, S-box
// x -> x^5, partial-round S-box on lane 0. Round constants come from
// `constants` as upstream's hex literals, which documents their provenance.
// ---------------------------------------------------------------------------

/// One frozen round constant, decoded from its hex literal.
///
/// `Fr` has no compile-time constructor, so this runs on every call: 80
/// decodes per permutation, measured at 1.76x on the permutation; no
/// benchmark on a real workload yet says it matters, so the obvious code
/// stays. The literals are checked against the reference dump in
/// `tests/poseidon2.rs`, and a malformed one panics here rather than becoming a
/// different field element.
#[inline]
fn rc(hex: &str) -> Fr {
    Fr::from_hex(hex).expect("a frozen round constant is a canonical hex literal")
}

/// `x^5`, the S-box. Three multiplications.
#[inline]
fn sbox(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

/// The external (full-round) linear layer at width 3: multiplication by the
/// circulant matrix `[[2,1,1],[1,2,1],[1,1,2]]`, which is adding the state sum
/// to every lane.
#[inline]
fn external_matrix(s: &mut [Fr; 3]) {
    let sum = s[0] + s[1] + s[2];
    s[0] += sum;
    s[1] += sum;
    s[2] += sum;
}

/// The internal (partial-round) linear layer at width 3: multiplication by
/// `1 + diag(1, 1, 2) = [[2,1,1],[1,2,1],[1,1,3]]`.
#[inline]
fn internal_matrix(s: &mut [Fr; 3]) {
    let sum = s[0] + s[1] + s[2];
    s[0] += sum;
    s[1] += sum;
    s[2] = s[2] + s[2] + sum;
}

/// The Poseidon2 permutation, in place.
pub fn poseidon2_permute(state: &mut [Fr; 3]) {
    external_matrix(state);

    for row in POSEIDON2_RC3_INITIAL.iter() {
        for lane in 0..3 {
            state[lane] = sbox(state[lane] + rc(row[lane]));
        }
        external_matrix(state);
    }

    for c in POSEIDON2_RC3_INTERNAL.iter() {
        state[0] = sbox(state[0] + rc(c));
        internal_matrix(state);
    }

    for row in POSEIDON2_RC3_TERMINAL.iter() {
        for lane in 0..3 {
            state[lane] = sbox(state[lane] + rc(row[lane]));
        }
        external_matrix(state);
    }
}

// ---------------------------------------------------------------------------
// The duplex sponge.
// ---------------------------------------------------------------------------

/// The sponge rate. Lanes `0..RATE` of the state are absorbed into and squeezed
/// from; lane `RATE` is the capacity and never leaves the sponge.
const RATE: usize = 2;

/// A domain-separation tag. Values live only in `constants::transcript_tags`.
pub type Tag = u64;

/// A record of one typed-layer operation.
///
/// Metadata only: the log never feeds the sponge, so it cannot affect a single
/// challenge. It exists so a prover phase can be told what a transcript did.
/// Raw [`Transcript::observe`] and [`Transcript::sample`] are not recorded —
/// they are the layer below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptEvent {
    /// A message absorbed under `tag`, carrying `n_scalars` payload field
    /// elements — the scalar count for `append_scalar`/`append_scalars`, the
    /// 31-byte chunk count for `append_bytes`. The framing elements (the tag
    /// and the length) are not counted.
    Absorb { tag: Tag, n_scalars: usize },
    /// A challenge drawn under `tag`.
    Challenge { tag: Tag },
}

/// A transcript's complete sponge state: enough to resume the challenge stream
/// exactly, and nothing else.
///
/// The event log is *not* captured — it is metadata, and a restored transcript
/// starts a fresh one.
///
/// Canonical by construction: buffer lanes at or past their length are zero and
/// no squeezed material outlives an absorb, so a snapshot is a deterministic
/// function of the operation sequence that produced it — replay the same script
/// and get the same bytes, which is what an archived phase boundary needs.
/// Serde enforces the shape on the way in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptSnapshot {
    state: [Fr; 3],
    input: [Fr; RATE],
    input_len: u8,
    output: [Fr; RATE],
    output_len: u8,
}

/// The Poseidon2 duplex transcript.
pub struct Transcript {
    /// Sponge state; lane 2 is the capacity.
    state: [Fr; 3],
    /// Absorbed but not yet permuted. Lanes at or past `input_len` are zero.
    input: [Fr; RATE],
    input_len: usize,
    /// Squeezed but not yet handed out. Lanes at or past `output_len` are zero;
    /// `sample` takes lane `output_len - 1`, so challenges leave the rate from
    /// the end.
    output: [Fr; RATE],
    output_len: usize,
    events: Vec<TranscriptEvent>,
}

// A `Default` impl would be a second name for `new` with no caller, which
// anti-goal 10 rules out; the lint has nothing to catch here.
#[allow(clippy::new_without_default)]
impl Transcript {
    /// A transcript with a zero sponge and empty buffers.
    ///
    /// Absorbing the protocol preamble is the caller's job, through the typed
    /// layer.
    pub fn new() -> Transcript {
        Transcript {
            state: [Fr::ZERO; 3],
            input: [Fr::ZERO; RATE],
            input_len: 0,
            output: [Fr::ZERO; RATE],
            output_len: 0,
            events: Vec::new(),
        }
    }

    /// Absorb one field element into the rate.
    ///
    /// Any squeezed-but-unread output is dropped. That is not what makes a
    /// challenge depend on the material absorbed before it — [`sample`]'s own
    /// guard already forces a fresh permutation whenever input is pending, and
    /// an absorb that filled the rate refilled the output on its way through.
    /// What dropping it buys is that the sponge state is a function of the
    /// operation sequence alone, which is what makes snapshots canonical. The
    /// reference challenger does the same.
    ///
    /// [`sample`]: Transcript::sample
    pub fn observe(&mut self, x: Fr) {
        self.output = [Fr::ZERO; RATE];
        self.output_len = 0;

        self.input[self.input_len] = x;
        self.input_len += 1;
        if self.input_len == RATE {
            self.duplex();
        }
    }

    /// Squeeze one field element.
    pub fn sample(&mut self) -> Fr {
        // Pending input must reach the sponge before it can affect a challenge,
        // and an empty output buffer needs a fresh permutation to refill.
        if self.input_len > 0 || self.output_len == 0 {
            self.duplex();
        }
        self.output_len -= 1;
        let out = self.output[self.output_len];
        self.output[self.output_len] = Fr::ZERO;
        out
    }

    /// One duplex step: absorb the pending input, permute, refill the output.
    ///
    /// Absorption is *overwrite*: the pending elements replace the rate rather
    /// than being added to it. An absorb of `n > 0` elements zero-fills the rest
    /// of the rate and adds `n` to the capacity, which is what keeps `[a]` and
    /// `[a, 0]` apart. A duplex step with nothing pending is a pure squeeze: it
    /// leaves the rate alone and adds nothing, so repeated squeezing just keeps
    /// permuting.
    fn duplex(&mut self) {
        let n = self.input_len;
        debug_assert!(n <= RATE, "the input buffer never exceeds the rate");

        for i in 0..n {
            self.state[i] = self.input[i];
            self.input[i] = Fr::ZERO;
        }
        self.input_len = 0;

        if n > 0 {
            for lane in self.state[n..RATE].iter_mut() {
                *lane = Fr::ZERO;
            }
            self.state[RATE] += Fr::from_u64(n as u64);
        }

        poseidon2_permute(&mut self.state);

        self.output.copy_from_slice(&self.state[..RATE]);
        self.output_len = RATE;
    }

    // -----------------------------------------------------------------------
    // Typed layer. Every message is `tag, length, payload...`.
    // -----------------------------------------------------------------------

    /// Absorb one scalar under `tag`. Exactly `append_scalars(tag, &[x])`.
    pub fn append_scalar(&mut self, tag: Tag, x: Fr) {
        self.append_scalars(tag, &[x]);
    }

    /// Absorb a length-delimited run of scalars under `tag`.
    pub fn append_scalars(&mut self, tag: Tag, xs: &[Fr]) {
        self.observe(Fr::from_u64(tag));
        self.observe(Fr::from_u64(xs.len() as u64));
        for x in xs {
            self.observe(*x);
        }
        self.events.push(TranscriptEvent::Absorb {
            tag,
            n_scalars: xs.len(),
        });
    }

    /// Absorb a length-delimited byte string under `tag`.
    ///
    /// The bytes are split into 31-byte little-endian chunks, the last one
    /// zero-padded. 31 bytes is `< 2^248 < p`, so every chunk is a canonical
    /// field element, and the byte length — not the chunk count — is what makes
    /// the encoding injective.
    pub fn append_bytes(&mut self, tag: Tag, bytes: &[u8]) {
        self.observe(Fr::from_u64(tag));
        self.observe(Fr::from_u64(bytes.len() as u64));
        for chunk in bytes.chunks(31) {
            let mut limb = [0u8; 32];
            limb[..chunk.len()].copy_from_slice(chunk);
            self.observe(
                Fr::from_bytes(&limb).expect("a 31-byte little-endian chunk is below 2^248 < p"),
            );
        }
        self.events.push(TranscriptEvent::Absorb {
            tag,
            n_scalars: bytes.len().div_ceil(31),
        });
    }

    /// Draw a challenge under `tag`.
    pub fn challenge_scalar(&mut self, tag: Tag) -> Fr {
        self.observe(Fr::from_u64(tag));
        let c = self.sample();
        self.events.push(TranscriptEvent::Challenge { tag });
        c
    }

    // -----------------------------------------------------------------------
    // Snapshot / restore / event log.
    // -----------------------------------------------------------------------

    /// Capture the sponge state and both buffers.
    pub fn snapshot(&self) -> TranscriptSnapshot {
        TranscriptSnapshot {
            state: self.state,
            input: self.input,
            input_len: self.input_len as u8,
            output: self.output,
            output_len: self.output_len as u8,
        }
    }

    /// Rebuild a transcript from a snapshot. It emits the same challenge stream
    /// the original would have, from the moment the snapshot was taken.
    ///
    /// The event log starts empty; events are metadata, not sponge state.
    pub fn restore(s: &TranscriptSnapshot) -> Transcript {
        Transcript {
            state: s.state,
            input: s.input,
            input_len: s.input_len as usize,
            output: s.output,
            output_len: s.output_len as usize,
            events: Vec::new(),
        }
    }

    /// Every typed-layer operation this transcript has performed, in order.
    pub fn event_log(&self) -> &[TranscriptEvent] {
        &self.events
    }
}

// ---------------------------------------------------------------------------
// Snapshot serde. Hand-written, like `Fr`'s, so no derive macro enters the
// build: a fixed 5-tuple, with `Fr` carrying the canonical little-endian rule.
// ---------------------------------------------------------------------------

impl serde::Serialize for TranscriptSnapshot {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (
            self.state,
            self.input,
            self.input_len,
            self.output,
            self.output_len,
        )
            .serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for TranscriptSnapshot {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<TranscriptSnapshot, D::Error> {
        let (state, input, input_len, output, output_len) =
            <([Fr; 3], [Fr; RATE], u8, [Fr; RATE], u8) as serde::Deserialize>::deserialize(d)?;

        // Reject anything `snapshot` could not have produced: over-long
        // buffers, or stale values in the lanes past a buffer's length.
        //
        // The input bound is strict. `observe` duplexes the moment the rate
        // fills, so a transcript is never handed back to a caller with a full
        // input buffer, and a snapshot claiming one would make the next
        // `observe` index past the end.
        if input_len as usize >= RATE
            || output_len as usize > RATE
            || input[input_len as usize..].iter().any(|x| *x != Fr::ZERO)
            || output[output_len as usize..].iter().any(|x| *x != Fr::ZERO)
        {
            return Err(<D::Error as serde::de::Error>::custom(
                "malformed transcript snapshot: buffer length or padding is not canonical",
            ));
        }

        Ok(TranscriptSnapshot {
            state,
            input,
            input_len,
            output,
            output_len,
        })
    }
}

// ---------------------------------------------------------------------------
// The public I/O digest.
// ---------------------------------------------------------------------------

/// The single `Fr` that binds a guest's fd 0 and fd 1 byte streams.
///
/// This is the value the statement-binding order absorbs as "public I/O
/// digest". Frozen at S10; later stages recompute it and never redefine it.
/// `docs/spec/ecall-abi.md` section 6 is normative, and it is the same recipe
/// the typed layer already runs:
///
/// ```text
///   input tag, input byte length, input limbs,
///   output tag, output byte length, output limbs,   then squeeze once
/// ```
///
/// Each stream is packed 31 bytes at a time into little-endian `Fr` limbs with
/// the final partial limb zero-extended, which is exactly
/// [`Transcript::append_bytes`]'s frozen encoding — so this function is two
/// typed messages and one raw squeeze, in a sponge of its own, the way
/// `sumcheck::witness_digest` and `pcs::accumulator_digest` are built. The
/// squeeze is a raw [`Transcript::sample`], not a challenge, because a
/// challenge under one of these tags would be one tag in two kinds.
///
/// Injectivity, which is what makes this a binding commitment to the pair: the
/// two tags are distinct constants and every limb is below `2^248`, so the
/// absorbed stream parses back uniquely — read the tag, read the length, and
/// the length says how many limbs follow. An empty stream contributes its tag
/// and a zero length and no limbs. Appending a zero byte to a stream changes
/// its length, and swapping two unequal streams swaps their tags.
pub fn io_digest(public_input: &[u8], public_output: &[u8]) -> Fr {
    let mut sponge = Transcript::new();
    sponge.append_bytes(
        constants::transcript_tags::PUBLIC_INPUT_STREAM,
        public_input,
    );
    sponge.append_bytes(
        constants::transcript_tags::PUBLIC_OUTPUT_STREAM,
        public_output,
    );
    sponge.sample()
}
