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
//! `#![no_std]`: guests and the no_std verifier core link it.

extern crate alloc;

use alloc::vec::Vec;

use field::Fr;

// ---------------------------------------------------------------------------
// Poseidon2, width 3, over the BN254 scalar field.
//
// 8 full rounds (4 initial, 4 terminal) around 56 partial rounds, S-box
// x -> x^5, partial-round S-box on lane 0. Round constants are upstream's hex
// literals, below, which documents their provenance.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Poseidon2 round constants, width 3, over the BN254 scalar field.
//
// Provenance: the `RC3` table of <https://github.com/HorizenLabs/poseidon2>,
// file `plain_implementations/src/poseidon2/poseidon2_instance_bn256.rs`, at
// commit 055bde3f4782731ba5f5ce5888a440a94327eaf3 — the same table Plonky3
// checks its BN254 Poseidon2 against. The literals below are copied from that
// file character for character, so the vendored table diffs against its source
// by eye; `field::Fr::from_hex` reads them, big-endian, as upstream writes them.
//
// `RC3` is 64 rows of 3 constants. The 4 initial full rounds (rows 0..4) and 4
// terminal full rounds (rows 60..64) use all three lanes; the 56 partial rounds
// (rows 4..60) use lane 0 only, and upstream stores zero in lanes 1 and 2 of
// those rows. The three tables below are exactly the entries the permutation
// reads, split by the phase that reads them.
//
// `crates/transcript/tests/poseidon2.rs` holds the permutation built on these
// three tables to 128 committed vectors that `tools/transcript-ref` computes
// from Plonky3's permutation and upstream's `RC3`, so the transcription is
// verified rather than trusted.
// ---------------------------------------------------------------------------

/// Round constants for the 4 initial full rounds: `RC3` rows 0..4, all lanes.
#[rustfmt::skip]
const POSEIDON2_RC3_INITIAL: [[&str; 3]; 4] = [
    [
        "0x1d066a255517b7fd8bddd3a93f7804ef7f8fcde48bb4c37a59a09a1a97052816",
        "0x29daefb55f6f2dc6ac3f089cebcc6120b7c6fef31367b68eb7238547d32c1610",
        "0x1f2cb1624a78ee001ecbd88ad959d7012572d76f08ec5c4f9e8b7ad7b0b4e1d1",
    ],
    [
        "0x0aad2e79f15735f2bd77c0ed3d14aa27b11f092a53bbc6e1db0672ded84f31e5",
        "0x2252624f8617738cd6f661dd4094375f37028a98f1dece66091ccf1595b43f28",
        "0x1a24913a928b38485a65a84a291da1ff91c20626524b2b87d49f4f2c9018d735",
    ],
    [
        "0x22fc468f1759b74d7bfc427b5f11ebb10a41515ddff497b14fd6dae1508fc47a",
        "0x1059ca787f1f89ed9cd026e9c9ca107ae61956ff0b4121d5efd65515617f6e4d",
        "0x02be9473358461d8f61f3536d877de982123011f0bf6f155a45cbbfae8b981ce",
    ],
    [
        "0x0ec96c8e32962d462778a749c82ed623aba9b669ac5b8736a1ff3a441a5084a4",
        "0x292f906e073677405442d9553c45fa3f5a47a7cdb8c99f9648fb2e4d814df57e",
        "0x274982444157b86726c11b9a0f5e39a5cc611160a394ea460c63f0b2ffe5657e",
    ],
];

/// Round constants for the 56 partial rounds: `RC3` rows 4..60, lane 0 only.
#[rustfmt::skip]
const POSEIDON2_RC3_INTERNAL: [&str; 56] = [
    "0x1a1d063e54b1e764b63e1855bff015b8cedd192f47308731499573f23597d4b5",
    "0x26abc66f3fdf8e68839d10956259063708235dccc1aa3793b91b002c5b257c37",
    "0x0c7c64a9d887385381a578cfed5aed370754427aabca92a70b3c2b12ff4d7be8",
    "0x1cf5998769e9fab79e17f0b6d08b2d1eba2ebac30dc386b0edd383831354b495",
    "0x0f5e3a8566be31b7564ca60461e9e08b19828764a9669bc17aba0b97e66b0109",
    "0x18df6a9d19ea90d895e60e4db0794a01f359a53a180b7d4b42bf3d7a531c976e",
    "0x04f7bf2c5c0538ac6e4b782c3c6e601ad0ea1d3a3b9d25ef4e324055fa3123dc",
    "0x29c76ce22255206e3c40058523748531e770c0584aa2328ce55d54628b89ebe6",
    "0x198d425a45b78e85c053659ab4347f5d65b1b8e9c6108dbe00e0e945dbc5ff15",
    "0x25ee27ab6296cd5e6af3cc79c598a1daa7ff7f6878b3c49d49d3a9a90c3fdf74",
    "0x138ea8e0af41a1e024561001c0b6eb1505845d7d0c55b1b2c0f88687a96d1381",
    "0x306197fb3fab671ef6e7c2cba2eefd0e42851b5b9811f2ca4013370a01d95687",
    "0x1a0c7d52dc32a4432b66f0b4894d4f1a21db7565e5b4250486419eaf00e8f620",
    "0x2b46b418de80915f3ff86a8e5c8bdfccebfbe5f55163cd6caa52997da2c54a9f",
    "0x12d3e0dc0085873701f8b777b9673af9613a1af5db48e05bfb46e312b5829f64",
    "0x263390cf74dc3a8870f5002ed21d089ffb2bf768230f648dba338a5cb19b3a1f",
    "0x0a14f33a5fe668a60ac884b4ca607ad0f8abb5af40f96f1d7d543db52b003dcd",
    "0x28ead9c586513eab1a5e86509d68b2da27be3a4f01171a1dd847df829bc683b9",
    "0x1c6ab1c328c3c6430972031f1bdb2ac9888f0ea1abe71cffea16cda6e1a7416c",
    "0x1fc7e71bc0b819792b2500239f7f8de04f6decd608cb98a932346015c5b42c94",
    "0x03e107eb3a42b2ece380e0d860298f17c0c1e197c952650ee6dd85b93a0ddaa8",
    "0x2d354a251f381a4669c0d52bf88b772c46452ca57c08697f454505f6941d78cd",
    "0x094af88ab05d94baf687ef14bc566d1c522551d61606eda3d14b4606826f794b",
    "0x19705b783bf3d2dc19bcaeabf02f8ca5e1ab5b6f2e3195a9d52b2d249d1396f7",
    "0x09bf4acc3a8bce3f1fcc33fee54fc5b28723b16b7d740a3e60cef6852271200e",
    "0x1803f8200db6013c50f83c0c8fab62843413732f301f7058543a073f3f3b5e4e",
    "0x0f80afb5046244de30595b160b8d1f38bf6fb02d4454c0add41f7fef2faf3e5c",
    "0x126ee1f8504f15c3d77f0088c1cfc964abcfcf643f4a6fea7dc3f98219529d78",
    "0x23c203d10cfcc60f69bfb3d919552ca10ffb4ee63175ddf8ef86f991d7d0a591",
    "0x2a2ae15d8b143709ec0d09705fa3a6303dec1ee4eec2cf747c5a339f7744fb94",
    "0x07b60dee586ed6ef47e5c381ab6343ecc3d3b3006cb461bbb6b5d89081970b2b",
    "0x27316b559be3edfd885d95c494c1ae3d8a98a320baa7d152132cfe583c9311bd",
    "0x1d5c49ba157c32b8d8937cb2d3f84311ef834cc2a743ed662f5f9af0c0342e76",
    "0x2f8b124e78163b2f332774e0b850b5ec09c01bf6979938f67c24bd5940968488",
    "0x1e6843a5457416b6dc5b7aa09a9ce21b1d4cba6554e51d84665f75260113b3d5",
    "0x11cdf00a35f650c55fca25c9929c8ad9a68daf9ac6a189ab1f5bc79f21641d4b",
    "0x21632de3d3bbc5e42ef36e588158d6d4608b2815c77355b7e82b5b9b7eb560bc",
    "0x0de625758452efbd97b27025fbd245e0255ae48ef2a329e449d7b5c51c18498a",
    "0x2ad253c053e75213e2febfd4d976cc01dd9e1e1c6f0fb6b09b09546ba0838098",
    "0x1d6b169ed63872dc6ec7681ec39b3be93dd49cdd13c813b7d35702e38d60b077",
    "0x1660b740a143664bb9127c4941b67fed0be3ea70a24d5568c3a54e706cfef7fe",
    "0x0065a92d1de81f34114f4ca2deef76e0ceacdddb12cf879096a29f10376ccbfe",
    "0x1f11f065202535987367f823da7d672c353ebe2ccbc4869bcf30d50a5871040d",
    "0x26596f5c5dd5a5d1b437ce7b14a2c3dd3bd1d1a39b6759ba110852d17df0693e",
    "0x16f49bc727e45a2f7bf3056efcf8b6d38539c4163a5f1e706743db15af91860f",
    "0x1abe1deb45b3e3119954175efb331bf4568feaf7ea8b3dc5e1a4e7438dd39e5f",
    "0x0e426ccab66984d1d8993a74ca548b779f5db92aaec5f102020d34aea15fba59",
    "0x0e7c30c2e2e8957f4933bd1942053f1f0071684b902d534fa841924303f6a6c6",
    "0x0812a017ca92cf0a1622708fc7edff1d6166ded6e3528ead4c76e1f31d3fc69d",
    "0x21a5ade3df2bc1b5bba949d1db96040068afe5026edd7a9c2e276b47cf010d54",
    "0x01f3035463816c84ad711bf1a058c6c6bd101945f50e5afe72b1a5233f8749ce",
    "0x0b115572f038c0e2028c2aafc2d06a5e8bf2f9398dbd0fdf4dcaa82b0f0c1c8b",
    "0x1c38ec0b99b62fd4f0ef255543f50d2e27fc24db42bc910a3460613b6ef59e2f",
    "0x1c89c6d9666272e8425c3ff1f4ac737b2f5d314606a297d4b1d0b254d880c53e",
    "0x03326e643580356bf6d44008ae4c042a21ad4880097a5eb38b71e2311bb88f8f",
    "0x268076b0054fb73f67cee9ea0e51e3ad50f27a6434b5dceb5bdde2299910a4c9",
];

/// Round constants for the 4 terminal full rounds: `RC3` rows 60..64, all lanes.
#[rustfmt::skip]
const POSEIDON2_RC3_TERMINAL: [[&str; 3]; 4] = [
    [
        "0x1acd63c67fbc9ab1626ed93491bda32e5da18ea9d8e4f10178d04aa6f8747ad0",
        "0x19f8a5d670e8ab66c4e3144be58ef6901bf93375e2323ec3ca8c86cd2a28b5a5",
        "0x1c0dc443519ad7a86efa40d2df10a011068193ea51f6c92ae1cfbb5f7b9b6893",
    ],
    [
        "0x14b39e7aa4068dbe50fe7190e421dc19fbeab33cb4f6a2c4180e4c3224987d3d",
        "0x1d449b71bd826ec58f28c63ea6c561b7b820fc519f01f021afb1e35e28b0795e",
        "0x1ea2c9a89baaddbb60fa97fe60fe9d8e89de141689d1252276524dc0a9e987fc",
    ],
    [
        "0x0478d66d43535a8cb57e9c1c3d6a2bd7591f9a46a0e9c058134d5cefdb3c7ff1",
        "0x19272db71eece6a6f608f3b2717f9cd2662e26ad86c400b21cde5e4a7b00bebe",
        "0x14226537335cab33c749c746f09208abb2dd1bd66a87ef75039be846af134166",
    ],
    [
        "0x01fd6af15956294f9dfe38c0d976a088b21c21e4a1c2e823f912f44961f9a9ce",
        "0x18e5abedd626ec307bca190b8b2cab1aaee2e62ed229ba5a5ad8518d4e5f2a57",
        "0x0fc1bbceba0590f5abbdffa6d3b35e3297c021a3a409926d0e2d54dc1c84fda6",
    ],
];

/// Domain-separation tags for the Poseidon2 duplex transcript.
///
/// Sequential `u64`, each assigned once: a value here is part of the absorbed
/// stream, so changing one changes the protocol.
///
/// `0` is deliberately not a tag, so an uninitialised tag can never be a valid
/// message. `13` is retired: no message carries it, and it is never
/// reassigned.
///
/// One round constant, decoded from its hex literal.
///
/// `Fr` has no compile-time constructor, so this runs on every call: 80
/// decodes per permutation, measured at 1.76x on the permutation; no
/// benchmark on a real workload says it matters, so the obvious code stays.
/// The literals are pinned through the permutation by the reference vectors
/// `tests/poseidon2.rs` replays, and a malformed one panics here rather than
/// becoming a different field element.
#[inline]
fn rc(hex: &str) -> Fr {
    Fr::from_hex(hex).expect("a round constant is a canonical hex literal")
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

// A `Default` impl would be a second name for `new` with no caller; the lint
// has nothing to catch here.
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

/// The single `Fr` that binds a statement's public input and public output
/// byte strings.
///
/// This is the value the global transcript absorbs at G7 as the "public I/O
/// digest"; the guest never computes it. `docs/spec/public-values.md` §5
/// specifies it, and it is the same recipe the typed layer already runs:
///
/// ```text
///   input tag, input byte length, input limbs,
///   output tag, output byte length, output limbs,   then squeeze once
/// ```
///
/// Each stream is packed 31 bytes at a time into little-endian `Fr` limbs with
/// the final partial limb zero-extended, which is exactly
/// [`Transcript::append_bytes`]'s encoding — so this function is two
/// typed messages and one raw squeeze, in a sponge of its own, the way
/// `sumcheck::witness_digest` is built. The
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
