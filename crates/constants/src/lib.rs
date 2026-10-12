#![no_std]
//! Constants and tags for the whole workspace.
//!
//! This crate holds constant items, a few `const fn` lookups over its own
//! tables, and doc comments: no traits, no macros, no tests. Guest-side code
//! links it, so it is `#![no_std]`.
//!
//! Changing any value here is a protocol change.

/// Protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// BN254 scalar field modulus `p`, little-endian 64-bit limbs.
///
/// `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
/// `  = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`
pub const FR_MODULUS: [u64; 4] = [
    0x43e1_f593_f000_0001,
    0x2833_e848_79b9_7091,
    0xb850_45b6_8181_585d,
    0x3064_4e72_e131_a029,
];

/// `p - 2`, little-endian 64-bit limbs: the Fermat exponent for inversion.
pub const FR_MODULUS_MINUS_TWO: [u64; 4] = [
    0x43e1_f593_efff_ffff,
    0x2833_e848_79b9_7091,
    0xb850_45b6_8181_585d,
    0x3064_4e72_e131_a029,
];

/// Montgomery radix `R = 2^256 mod p`, little-endian 64-bit limbs.
///
/// `R` is also the Montgomery representation of `1`.
pub const FR_R: [u64; 4] = [
    0xac96_341c_4fff_fffb,
    0x36fc_7695_9f60_cd29,
    0x666e_a36f_7879_462e,
    0x0e0a_77c1_9a07_df2f,
];

/// `R^2 mod p`, little-endian 64-bit limbs: converts a canonical value into
/// Montgomery form via one Montgomery multiplication.
pub const FR_R2: [u64; 4] = [
    0x1bb8_e645_ae21_6da7,
    0x53fe_3ab1_e35c_59e3,
    0x8c49_833d_53bb_8085,
    0x0216_d0b1_7f4e_44a5,
];

/// `-p^{-1} mod 2^64`, the per-limb Montgomery reduction multiplier.
pub const FR_INV: u64 = 0xc2e1_f593_efff_ffff;

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
pub const POSEIDON2_RC3_INITIAL: [[&str; 3]; 4] = [
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
pub const POSEIDON2_RC3_INTERNAL: [&str; 56] = [
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
pub const POSEIDON2_RC3_TERMINAL: [[&str; 3]; 4] = [
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
/// message.
///
/// **One tag, one message kind.** The typed layer frames every message as
/// `tag, length, payload...` and nothing more, so injectivity of the absorbed
/// stream rests on each tag naming exactly one kind of message — scalars *or*
/// bytes *or* a challenge, never two. Each constant below records its kind.
/// Adding a tag is free; reusing one across kinds is a soundness bug. See
/// `docs/spec/transcript.md` §4.
pub mod transcript_tags {
    /// Scalars. The protocol suite and version preamble, `[PROTOCOL_VERSION]`:
    /// the first message of the statement's global transcript
    /// (`docs/spec/proof.md` §2, G1). The shard transcripts and the identity
    /// and I/O sponges open with their own tags instead.
    pub const PROTOCOL_SUITE: u64 = 1;

    /// Bytes. The statement's public inputs / public I/O.
    pub const PUBLIC_INPUTS: u64 = 2;

    /// Scalars. One sumcheck round polynomial's coefficients.
    pub const SUMCHECK_ROUND: u64 = 3;

    /// Challenge. Every challenge a sumcheck draws: first the `n` eq-randomizers
    /// `r` that fix the zerocheck's equality polynomial, then the per-round
    /// challenge for the round just absorbed. One tag, one kind; the two roles
    /// are separated by their fixed position in the transcript script, not by
    /// their tag.
    pub const SUMCHECK_CHALLENGE: u64 = 4;

    /// Scalars. The single squeezed `Fr` that binds a witness's columns to the
    /// transcript before any challenge is drawn over them. The same tag frames
    /// the messages inside the separate sponge that produces it; see
    /// `crates/sumcheck`.
    pub const WITNESS_DIGEST: u64 = 5;

    /// Scalars. A sumcheck's `final_evals`: the claimed value of every input
    /// polynomial at the fully bound point, absorbed before any later challenge.
    pub const SUMCHECK_FINAL_EVALS: u64 = 6;

    /// Bytes. The statement's public input inside `io_digest`'s own sponge.
    /// Absorbed first, before the output, which is what domain-separates the
    /// two. `docs/spec/public-values.md` §5.
    pub const PUBLIC_INPUT_STREAM: u64 = 7;

    /// Bytes. The statement's public output, the journal, inside
    /// `io_digest`'s own sponge, absorbed second. Distinct from
    /// [`PUBLIC_INPUT_STREAM`] so that swapping two unequal byte strings
    /// changes the digest. `docs/spec/public-values.md` §5.
    pub const PUBLIC_OUTPUT_STREAM: u64 = 8;

    /// Scalars. The first message of the program-identity sponge: the single
    /// element `code version`. It is what opens that sponge, so the identity
    /// is domain-separated from every other digest in the protocol.
    /// `docs/spec/program.md` §8. Also the global transcript's G6 message,
    /// `[identity]` (`docs/spec/proof.md` §2).
    pub const PROGRAM_IDENTITY: u64 = 9;

    /// Scalars. The static `VmConfig`: the family ids in ascending order, then
    /// their heights in the same order, then `bytecode_size_words`. The first
    /// of the statement descriptor's three messages, and the second message of
    /// the program-identity sponge.
    pub const VM_CONFIG: u64 = 10;

    /// Scalars. The per-proof shard count of every family in the `VmConfig`,
    /// in the same ascending order. The second of the statement descriptor's
    /// three messages, always absorbed immediately after the [`VM_CONFIG`]
    /// message it counts shards for and before [`MEMORY_WINDOWS`].
    pub const SHARD_COUNTS: u64 = 11;

    /// Scalars. A GKR circuit's claimed output tables, output-map order, as
    /// one message, absorbed before the top-layer point is drawn so that no
    /// output can be chosen after the point is known. `docs/spec/gkr.md` §5.2.
    pub const GKR_OUTPUTS: u64 = 12;

    /// Challenge. One coordinate of a GKR circuit's top-layer point, drawn
    /// after [`GKR_OUTPUTS`].
    pub const GKR_OUTPUT_POINT: u64 = 13;

    /// Challenge. The RLC that batches a layer transition's claims — one per
    /// column of the layer written, then its enforcing gates — into the one
    /// claim its sumcheck proves. Drawn after every claim it batches is
    /// absorbed.
    pub const GKR_BATCH: u64 = 14;

    /// Scalars. The claimed values of the layer a transition reads, at the
    /// point its sumcheck bound, in one message: one per column, or both
    /// children per column for a halving transition.
    pub const GKR_LAYER_CLAIMS: u64 = 15;

    /// Challenge. The point `τ` on the line through a halving transition's
    /// two child claims, drawn after both are absorbed.
    pub const GKR_CHILD: u64 = 16;

    /// Scalars. The statement's RAM window list `[w_1 … w_k]`, the
    /// `ZERO_WINDOWS` family's shard windows ascending, absorbed immediately
    /// after [`SHARD_COUNTS`] and before program identity.
    /// `docs/spec/memory.md` §6.1.
    pub const MEMORY_WINDOWS: u64 = 17;

    /// Scalars. The 64 register and pc boundary scalars
    /// `[t_0 … t_31, t_pc, v_1 … v_31]`, one message, absorbed after the
    /// statement's public values and before the memory challenges are drawn.
    /// `docs/spec/memory.md` §4.1 and §6.1.
    pub const MEMORY_BOUNDARY: u64 = 18;

    /// Scalars. The program-identity sponge's `entry_pc`, one element,
    /// absorbed after [`VM_CONFIG`]: its last message.
    /// `docs/spec/program.md` §8.
    pub const PROGRAM_ENTRY: u64 = 19;

    /// Challenge. The LogUp channels' two shard-local challenges, `g` then
    /// `β`, drawn in that order after the shard's seed and timestamp window.
    /// One tag, one kind; the two roles are separated by their fixed position
    /// in the shard's script, as [`SUMCHECK_CHALLENGE`]'s are.
    /// `docs/spec/lookup.md` §2.
    pub const LOOKUP_CHALLENGE: u64 = 20;

    /// Challenge. The global memory challenges `γ_M, α_addr, α_ts, α_val`,
    /// drawn in that order after the boundary scalars. One tag, one kind; the
    /// four roles are separated by position. `docs/spec/proof.md` §2.
    pub const MEMORY_CHALLENGE: u64 = 21;

    /// Challenge. The global state digest, drawn once after the memory
    /// challenges; every shard transcript is seeded with it.
    /// `docs/spec/proof.md` §2.
    pub const GLOBAL_STATE_DIGEST: u64 = 22;

    /// Scalars. `[global state digest, family, shard index]`, the first message
    /// of every shard transcript. `docs/spec/proof.md` §4.
    pub const SHARD_SEED: u64 = 23;

    /// Scalars. `[start, end]`, the shard's timestamp window, immediately after
    /// the seed. `docs/spec/proof.md` §4.
    pub const SHARD_TS_WINDOW: u64 = 24;

    /// Every tag's name, indexed by `tag - 1`. **Documentation, never
    /// semantics**, as `challenge_slot::NAMES` is: the number is the tag, and
    /// nothing reads a name to decide anything. `checker::tape` renders a
    /// transcript's absorb sequence with them, which is what makes a tape
    /// diffable against the order `docs/spec/proof.md` §2 specifies.
    ///
    /// One entry per tag above. The lookup itself lives in `checker::tape`.
    pub const NAMES: [&str; 24] = [
        "PROTOCOL_SUITE",
        "PUBLIC_INPUTS",
        "SUMCHECK_ROUND",
        "SUMCHECK_CHALLENGE",
        "WITNESS_DIGEST",
        "SUMCHECK_FINAL_EVALS",
        "PUBLIC_INPUT_STREAM",
        "PUBLIC_OUTPUT_STREAM",
        "PROGRAM_IDENTITY",
        "VM_CONFIG",
        "SHARD_COUNTS",
        "GKR_OUTPUTS",
        "GKR_OUTPUT_POINT",
        "GKR_BATCH",
        "GKR_LAYER_CLAIMS",
        "GKR_CHILD",
        "MEMORY_WINDOWS",
        "MEMORY_BOUNDARY",
        "PROGRAM_ENTRY",
        "LOOKUP_CHALLENGE",
        "MEMORY_CHALLENGE",
        "GLOBAL_STATE_DIGEST",
        "SHARD_SEED",
        "SHARD_TS_WINDOW",
    ];
}

/// The external challenge slots a GKR circuit's coefficients may name. A slot
/// number is never reassigned.
///
/// A `constraints::Coeff::Challenge(slot)` names one of these numbers, and the
/// caller supplies its value in `ExternalChallenges`. The number is the
/// semantics; [`challenge_slot::NAMES`] is documentation for dumps and
/// diagnostics, indexed by slot, exactly as a tag's constant name is.
pub mod challenge_slot {
    /// The test circuits' one challenge. No production circuit reads it.
    pub const TOY: u32 = 0;

    /// `γ_M`, the memory tuple's additive challenge. Drawn once per
    /// statement, after everything `docs/spec/memory.md` §6.1 absorbs.
    pub const MEM_GAMMA: u32 = 1;

    /// `α_addr`, the weight of a memory tuple's address. Drawn.
    /// `docs/spec/memory.md` §1.
    pub const MEM_ALPHA_ADDR: u32 = 2;

    /// `α_ts`, the weight of a memory tuple's timestamp. Drawn.
    /// `docs/spec/memory.md` §1.
    pub const MEM_ALPHA_TS: u32 = 3;

    /// `α_val`, the weight of a memory tuple's value. Drawn.
    /// `docs/spec/memory.md` §1.
    pub const MEM_ALPHA_VAL: u32 = 4;

    /// A RAM window shard's constant `γ_M + RAM + α_addr·4h·w`. **Derived,
    /// not drawn**: the verifier computes it from slots 1 and 2 and the window
    /// id bound in the statement, and never reads it from a proof.
    /// `docs/spec/memory.md` §3.3.
    pub const MEM_WINDOW_CONSTANT: u32 = 5;

    /// `g`, the LogUp channels' additive challenge. Drawn **per shard**, from
    /// that shard's own transcript, after its seed and timestamp window.
    /// `docs/spec/lookup.md` §2.
    pub const LOOKUP_G: u32 = 6;

    /// `β`, the LogUp tuple-compression challenge: a tuple is
    /// `Σ_j β^j·col_j`, `β^0` being the literal 1. Drawn per shard,
    /// immediately after [`LOOKUP_G`].
    pub const LOOKUP_BETA: u32 = 7;

    /// `β^2`. **Derived**: a gate coefficient is one literal or one challenge,
    /// so every power above the first is a slot of its own, computed by the
    /// verifier from [`LOOKUP_BETA`] and never read from a proof.
    pub const LOOKUP_BETA_2: u32 = 8;
    /// `β^3`, derived.
    pub const LOOKUP_BETA_3: u32 = 9;
    /// `β^4`, derived.
    pub const LOOKUP_BETA_4: u32 = 10;
    /// `β^5`, derived.
    pub const LOOKUP_BETA_5: u32 = 11;
    /// `β^6`, derived.
    pub const LOOKUP_BETA_6: u32 = 12;

    /// `β^j`'s slot for `j = 1 ..= 6`, indexed by `j - 1`. `β^0` is the
    /// literal 1 and has no slot, which is why a range channel's one-column
    /// tuple names no power at all.
    pub const LOOKUP_BETA_POWERS: [u32; 6] = [
        LOOKUP_BETA,
        LOOKUP_BETA_2,
        LOOKUP_BETA_3,
        LOOKUP_BETA_4,
        LOOKUP_BETA_5,
        LOOKUP_BETA_6,
    ];

    /// `g − Σ_{j < W} β^j`, the decoder channel's denominator at a padding
    /// row, `W` being that circuit's decoder tuple width. **Derived**: the
    /// decoder's neutral tuple is `MINUS_ONE` in every column
    /// (`docs/spec/lookup.md` §5), and a `Coeff` is one literal or one
    /// challenge, so the sum it compresses to is a slot rather than a
    /// constant.
    pub const LOOKUP_DECODER_NEUTRAL: u32 = 13;

    /// Every slot's display name, indexed by slot number.
    pub const NAMES: [&str; 14] = [
        "toy",
        "mem_gamma",
        "mem_alpha_addr",
        "mem_alpha_ts",
        "mem_alpha_val",
        "mem_window_constant",
        "lookup_g",
        "lookup_beta",
        "lookup_beta_2",
        "lookup_beta_3",
        "lookup_beta_4",
        "lookup_beta_5",
        "lookup_beta_6",
        "lookup_decoder_neutral",
    ];
}

/// The lookup channels a lookup expression names. A channel number is never
/// reassigned.
///
/// A `LookupExpr`'s `channel` is one of these numbers. A channel is either a
/// **range** channel, whose one expression holds on a row when its canonical
/// integer is below `2^BITS[channel]`, or a **table** channel, whose tuple
/// holds when it is a row of the channel's table, a set of setup columns.
/// [`lookup_channel::NAMES`] is documentation, indexed by channel, as
/// [`challenge_slot::NAMES`] is. `docs/spec/lookup.md` §1 and §3.
pub mod lookup_channel {
    /// Range. The timestamp gap's two 19-bit chunks: `[0, 2^19)`.
    pub const TIMESTAMP: u32 = 0;

    /// Range. A halfword, `[0, 2^16)`: two of them bound a 32-bit value, under
    /// the range convention of `docs/spec/memory.md` §7.
    pub const RANGE16: u32 = 1;

    /// Table. The generic tables, packed into one table under the gated-key
    /// convention of `docs/spec/lookup.md` §4.
    pub const GENERIC: u32 = 2;

    /// Table. A family's decoded instruction table, `crates/program`'s
    /// `lookup_tuple(family)` columns in their fixed order.
    pub const DECODER: u32 = 3;

    /// How many channels this table defines.
    pub const COUNT: u32 = 4;

    /// Whether channel `i` is a range channel, indexed by channel. A range
    /// channel's table is the closed form of `docs/spec/lookup.md` §3; a table
    /// channel's is setup columns.
    pub const IS_RANGE: [bool; COUNT as usize] = [true, true, false, false];

    /// A range channel's bound, as a bit width, indexed by channel; 0 where
    /// [`IS_RANGE`] is false, which is not a bound of `[0, 1)` but the absence
    /// of one.
    ///
    /// This is a **bound**, not a table size: what decides the fewest
    /// variables a circuit declaring a channel may be built at is
    /// `constraints::lookup::table_vars`, which reads this for a range channel.
    pub const BITS: [u32; COUNT as usize] = [19, 16, 0, 0];

    /// Every channel's display name, indexed by channel.
    pub const NAMES: [&str; COUNT as usize] = ["timestamp", "range16", "generic", "decoder"];

    /// The widest lookup tuple any channel carries: `beta` powers exist for
    /// positions `0 .. MAX_TUPLE`, and `challenge_slot::LOOKUP_BETA_POWERS`
    /// has one slot per position above 0. The decoder's seven-column tuple is
    /// the widest built (`crates/program`'s `lookup_tuple`).
    pub const MAX_TUPLE: usize = 7;
}

/// The generic channel's packed table: its width and key bases.
/// `crates/program`'s `lookup_tables` builds the table; its numbers live here
/// because a circuit, which cannot depend on `program`, builds keys into it.
/// `docs/spec/lookup.md` §9.
///
/// ```text
/// row 0                     the ZeroEntry, all zero
/// rows 1 ..= 2^16           AND:         (AND_BASE   + a + 1,  b,        a & b)
/// rows 2^16+1 ..= 2^17      U16GetSign:  (SIGN_BASE  + h + 1,  h >> 15,  0)
/// rows 2^17+1 ..= 2^17+32   ShiftPowers: (SHIFT_BASE + s + 1,  2^s,      2^(31−s))
/// ```
pub mod generic_table {
    /// The table's tuple width: a key and two values.
    pub const WIDTH: usize = 3;

    /// The AND byte table's key base: its keys are `AND_BASE + a + 1` for
    /// `a < 256`.
    pub const AND_BASE: u32 = 0;

    /// `U16GetSign`'s key base, one past the AND table's highest key: its keys
    /// are `SIGN_BASE + h + 1` for every halfword `h`, disjoint from AND's.
    pub const SIGN_BASE: u32 = 256;

    /// `ShiftPowers`' key base, one past `U16GetSign`'s highest key: its keys
    /// are `SHIFT_BASE + s + 1` for every shift amount `s < 32`, disjoint from
    /// both ranges below it.
    pub const SHIFT_BASE: u32 = SIGN_BASE + (1 << 16);

    /// `ShiftPowers`' rows: one per shift amount a RV32 shift can take and
    /// none other, so a key past the last of them matches no row of the packed
    /// table at all (`docs/spec/shift-bitwise.md` §3.1).
    pub const SHIFT_ROWS: usize = 32;

    /// The exponent `ShiftPowers`' two values sum to: row `s` is
    /// `(2^s, 2^(SHIFT_COPOWER_BITS − s))`, so their product is
    /// `2^SHIFT_COPOWER_BITS` on every row.
    ///
    /// **It is 31, not 32.** The copower a residue bound needs is `2^(32 − s)`,
    /// which at `s = 0` is `2^32` and does not fit the packed table's `u32`
    /// columns; the table stores half of it and the two gates that read it
    /// carry the compensating factor 2 (`docs/spec/shift-bitwise.md` §3.1).
    pub const SHIFT_COPOWER_BITS: u32 = 31;
}

/// The circuit families, by number. A family number is never reassigned.
///
/// A family is one arithmetization shape covering a set of program counters.
/// The number is what everything else cites: canonical ordering is ascending
/// `FamilyId`, the program-identity digest absorbs families in that order, and
/// shard transcripts are seeded with it. Ids 0–6 are the execution families and
/// 7–11 the window families (`docs/spec/circuits.md` §1).
///
/// Which mnemonic each instruction family claims is `crates/program`'s
/// `row_kind`, and `docs/spec/program.md` §4 is the table.
pub mod family {
    /// `add`, `sub`, `addi`, `lui`, `auipc`, and the system row kind:
    /// `ecall`, `ebreak`, `fence`.
    pub const ADD_SUB_LUI_AUIPC: u32 = 0;
    /// `jal`, `jalr`, the six branches, `slt`, `sltu`, `slti`, `sltiu`.
    pub const JUMP_BRANCH_SLT: u32 = 1;
    /// The six shifts and the six bitwise operations.
    pub const SHIFT_BITWISE: u32 = 2;
    /// The eight M-extension operations.
    pub const MUL_DIV: u32 = 3;
    /// `lw`, `sw`.
    pub const MEM_WORD: u32 = 4;
    /// `lb`, `lh`, `lbu`, `lhu`, `sb`, `sh`.
    pub const MEM_SUBWORD: u32 = 5;
    /// `lr.w`, `sc.w` and the nine AMOs.
    pub const ATOMICS: u32 = 6;
    /// Memory initialisation and teardown of RAM window 0, the image window:
    /// exactly one shard. Claims no pc; present in every `VmConfig`, at the
    /// height of [`ZERO_WINDOWS`]. `docs/spec/memory.md` §3.
    pub const INIT_TEARDOWN: u32 = 7;
    /// Memory initialisation and teardown of the zero-initialized RAM windows
    /// above window 0, one shard per window the execution touches. Claims no
    /// pc; present in every `VmConfig`, at the height of [`INIT_TEARDOWN`].
    /// `docs/spec/memory.md` §3.
    pub const ZERO_WINDOWS: u32 = 8;
    /// The **public input** window: the verifier-known input of the
    /// statement, at [`guest_memory::PUBLIC_INPUT_ORIGIN`]. Claims no pc,
    /// owns no cycle, and is in **every** `VmConfig` at
    /// [`PUBLIC_WINDOW_HEIGHT`], proving exactly one shard.
    ///
    /// Its init column is what the verifier holds to the statement's `input`;
    /// its teardown column is free, because a guest may overwrite its own
    /// input buffer (`docs/spec/public-values.md` §5).
    pub const PUBLIC_INPUT: u32 = 9;
    /// The **public output** window — the journal — at
    /// [`guest_memory::PUBLIC_OUTPUT_ORIGIN`]. In every `VmConfig` at
    /// [`PUBLIC_WINDOW_HEIGHT`], proving exactly one shard.
    ///
    /// Its init leaf is the **literal 0** of [`ZERO_WINDOWS`]' artifact, which
    /// is what stops a prover supplying the journal at timestamp 0 instead of
    /// storing it; its teardown column is what the verifier holds to the
    /// statement's `output` (`docs/spec/public-values.md` §5).
    pub const PUBLIC_OUTPUT: u32 = 10;
    /// The **advice** windows: prover-supplied initial values for the
    /// region at [`guest_memory::ADVICE_ORIGIN`], one shard per window, `k`
    /// of them counted from [`guest_memory::ADVICE_ORIGIN`] upward. In every
    /// `VmConfig` at the window height, with `k >= 0` shards.
    ///
    /// **Nothing binds its init column, by design.** Advice is what the
    /// prover chose; a guest owes a check of it against something public
    /// (`docs/spec/public-values.md` §6).
    pub const ADVICE_WINDOWS: u32 = 11;

    /// How many families this table defines.
    pub const COUNT: u32 = 12;

    /// The pinned height of [`PUBLIC_INPUT`] and [`PUBLIC_OUTPUT`].
    ///
    /// **Pinned by arithmetic, not by taste, and `2^12` is the ceiling.** A
    /// window's first address is `4 * height * window`, so the height is what
    /// places the windows, and both must sit in the hole
    /// `[0, guest_memory::RAM_ORIGIN)` that no RAM window family initializes —
    /// 64 KiB, and not a byte more without moving every program's load address.
    /// Two windows of `2^12` are `2 * 16 KiB` and land on
    /// [`guest_memory::PUBLIC_INPUT_ORIGIN`] = `0x8000` and
    /// [`guest_memory::PUBLIC_OUTPUT_ORIGIN`] = `0xC000`, ending flush against
    /// `RAM_ORIGIN`; `[0, 0x8000)` stays a hole, which is where the null
    /// dereference argument lives. `2^14` would need 128 KiB for two windows
    /// and leaves only window 0 in the hole — and window 0 initializes address
    /// 0, so a null dereference would balance. There is no step above this one.
    ///
    /// 16,380 payload bytes is what the geometry allows
    /// (`docs/spec/public-values.md` §9).
    ///
    /// The price is the verifier's step 10c, two 4,096-point multilinear
    /// evaluations — 4,095 `Fr` multiplies and 81,920 live bytes a shard
    /// (`2^11` `Fr` of fold scratch plus the 4,096 `u32` words of the window
    /// itself), 8,190 and 163,840 across the two.
    pub const PUBLIC_WINDOW_HEIGHT: u32 = 1 << 12;

    /// [`PUBLIC_INPUT`]'s window id at [`PUBLIC_WINDOW_HEIGHT`].
    pub const PUBLIC_INPUT_WINDOW: u32 =
        crate::guest_memory::PUBLIC_INPUT_ORIGIN / (4 * PUBLIC_WINDOW_HEIGHT);
    /// [`PUBLIC_OUTPUT`]'s window id at [`PUBLIC_WINDOW_HEIGHT`].
    pub const PUBLIC_OUTPUT_WINDOW: u32 =
        crate::guest_memory::PUBLIC_OUTPUT_ORIGIN / (4 * PUBLIC_WINDOW_HEIGHT);

    /// Whether a family's rows are **execution cycles**, indexed by
    /// `FamilyId`.
    ///
    /// The seven instruction families own cycles; the window families own
    /// addresses — a RAM window's rows are words, not cycles
    /// (`docs/spec/memory.md` §3). A block's time-window rules apply to
    /// cycle-owning families alone (`docs/spec/proof.md` §8): only their
    /// shards partition an execution in time.
    pub const CYCLE_OWNING: [bool; COUNT as usize] = [
        true,  // ADD_SUB_LUI_AUIPC
        true,  // JUMP_BRANCH_SLT
        true,  // SHIFT_BITWISE
        true,  // MUL_DIV
        true,  // MEM_WORD
        true,  // MEM_SUBWORD
        true,  // ATOMICS
        false, // INIT_TEARDOWN
        false, // ZERO_WINDOWS
        false, // PUBLIC_INPUT
        false, // PUBLIC_OUTPUT
        false, // ADVICE_WINDOWS
    ];

    /// The trace-height menu, ascending: the heights the registries build
    /// circuits at.
    ///
    /// What closes a height to a family is a channel whose **table needs more
    /// variables**, not carrying a channel at all: `constraints::lookup::
    /// table_vars` is 19 for `TIMESTAMP` and 16 for `RANGE16`, while `GENERIC`
    /// and `DECODER` report **0** — their tables are setup columns rather than
    /// closed forms, so they raise the floor by nothing.
    /// `constraints::family_circuit` returns `None` below the widest table its
    /// channels declare, and nothing rests on the two zeros: every family
    /// reading `GENERIC` also carries `TIMESTAMP`, whose 19 puts it at `2^20`
    /// regardless.
    ///
    /// `2^12` is the two **public-value** families' and nothing else's: it is
    /// below every channel floor an execution family reaches, and a window
    /// family at `2^12` reaches `0x4000`, short of the public windows' end, so
    /// `verifier_core::window_height` refuses it.
    pub const HEIGHT_MENU: [u32; 5] = [1 << 12, 1 << 16, 1 << 18, 1 << 20, 1 << 22];

    /// The default trace height of every family, indexed by `FamilyId`.
    ///
    /// **No execution family defaults below `2^20`.** A circuit carrying a
    /// timestamp gap obligation needs `lookup_channel::BITS[TIMESTAMP] = 19`
    /// variables (`docs/spec/lookup.md` §3), and `2^20` is the first height
    /// of [`HEIGHT_MENU`] that has them, so it is the floor for every family
    /// that runs cycles.
    pub const DEFAULT_HEIGHTS: [u32; COUNT as usize] = [
        1 << 22, // ADD_SUB_LUI_AUIPC
        1 << 22, // JUMP_BRANCH_SLT
        1 << 22, // SHIFT_BITWISE
        1 << 20, // MUL_DIV
        1 << 22, // MEM_WORD
        1 << 22, // MEM_SUBWORD
        1 << 20, // ATOMICS
        1 << 22, // INIT_TEARDOWN
        1 << 22, // ZERO_WINDOWS
        1 << 12, // PUBLIC_INPUT, and it is the only admissible one
        1 << 12, // PUBLIC_OUTPUT, likewise
        1 << 22, // ADVICE_WINDOWS, at the window height
    ];

    /// The default `bytecode_size_words`: `2^20` words, a 4 MiB ceiling on the
    /// span from `RAM_ORIGIN` to the last file-backed byte of the image.
    pub const DEFAULT_BYTECODE_SIZE_WORDS: u32 = 1 << 20;

    /// The version of the decoded-table construction. Absorbed first into the
    /// program-identity sponge. Changing it re-registers every program.
    pub const CODE_VERSION: u32 = 0;
}

/// The bit positions of `family_extra_mask`, per family. A bit position is
/// never reassigned (`docs/spec/program.md` §6).
///
/// Every live row's mask is **one-hot**: exactly one bit is set, naming the
/// row's kind, which is its mnemonic — except the add/sub/lui/auipc family's
/// bit 0, the *system* row kind shared by `ecall`, `ebreak` and `fence`, whose
/// rows tell the three apart by the `imm` codes in [`system_code`]. A circuit
/// unpacks the mask into selector bits, and one-hotness then comes from the
/// decoded table's domain rather than from a constraint.
///
/// Within a family the bits are in canonical ascending order: ascending
/// `(opcode, funct3, funct7)` of the encoding, `funct5` for the atomics. The
/// system kind is pinned to bit 0 ahead of that order.
pub mod extra_mask {
    /// `family::ADD_SUB_LUI_AUIPC`.
    pub mod add_sub_lui_auipc {
        pub const SYSTEM: u32 = 0;
        pub const ADDI: u32 = 1;
        pub const AUIPC: u32 = 2;
        pub const ADD: u32 = 3;
        pub const SUB: u32 = 4;
        pub const LUI: u32 = 5;
    }

    /// `family::JUMP_BRANCH_SLT`.
    pub mod jump_branch_slt {
        pub const SLTI: u32 = 0;
        pub const SLTIU: u32 = 1;
        pub const SLT: u32 = 2;
        pub const SLTU: u32 = 3;
        pub const BEQ: u32 = 4;
        pub const BNE: u32 = 5;
        pub const BLT: u32 = 6;
        pub const BGE: u32 = 7;
        pub const BLTU: u32 = 8;
        pub const BGEU: u32 = 9;
        pub const JALR: u32 = 10;
        pub const JAL: u32 = 11;
    }

    /// `family::SHIFT_BITWISE`.
    pub mod shift_bitwise {
        pub const SLLI: u32 = 0;
        pub const XORI: u32 = 1;
        pub const SRLI: u32 = 2;
        pub const SRAI: u32 = 3;
        pub const ORI: u32 = 4;
        pub const ANDI: u32 = 5;
        pub const SLL: u32 = 6;
        pub const XOR: u32 = 7;
        pub const SRL: u32 = 8;
        pub const SRA: u32 = 9;
        pub const OR: u32 = 10;
        pub const AND: u32 = 11;
    }

    /// `family::MUL_DIV`.
    pub mod mul_div {
        pub const MUL: u32 = 0;
        pub const MULH: u32 = 1;
        pub const MULHSU: u32 = 2;
        pub const MULHU: u32 = 3;
        pub const DIV: u32 = 4;
        pub const DIVU: u32 = 5;
        pub const REM: u32 = 6;
        pub const REMU: u32 = 7;
    }

    /// `family::MEM_WORD`.
    pub mod mem_word {
        pub const LW: u32 = 0;
        pub const SW: u32 = 1;
    }

    /// `family::MEM_SUBWORD`.
    pub mod mem_subword {
        pub const LB: u32 = 0;
        pub const LH: u32 = 1;
        pub const LBU: u32 = 2;
        pub const LHU: u32 = 3;
        pub const SB: u32 = 4;
        pub const SH: u32 = 5;
    }

    /// `family::ATOMICS`, ascending `funct5`. `aq` and `rl` are not recorded:
    /// on a single hart they order nothing.
    pub mod atomics {
        pub const AMOADD_W: u32 = 0;
        pub const AMOSWAP_W: u32 = 1;
        pub const LR_W: u32 = 2;
        pub const SC_W: u32 = 3;
        pub const AMOXOR_W: u32 = 4;
        pub const AMOOR_W: u32 = 5;
        pub const AMOAND_W: u32 = 6;
        pub const AMOMIN_W: u32 = 7;
        pub const AMOMAX_W: u32 = 8;
        pub const AMOMINU_W: u32 = 9;
        pub const AMOMAXU_W: u32 = 10;
    }

    /// The `imm` of a system row, which is how its one mask bit tells its
    /// three instructions apart. `ECALL` and `EBREAK` are their encodings'
    /// own `funct12`; `FENCE` is every fence, whatever its `pred`, `succ` and
    /// `fm`, because on one hart every fence is a no-op.
    pub mod system_code {
        pub const ECALL: u32 = 0;
        pub const EBREAK: u32 = 1;
        pub const FENCE: u32 = 2;
    }
}

/// The guest memory map.
///
/// RAM is the one region a program is loaded into. `crates/guest-sdk/link.ld`
/// states the same two numbers for the linker, `docs/spec/ecall-abi.md` §5
/// states them for a reader, and `crates/constants/tests/ecall_abi.rs` checks
/// all three against each other — a memory map written down three times is a
/// memory map that can disagree with itself.
///
/// `crates/loader` refuses a `PT_LOAD` segment that does not lie inside this
/// window. Outside it a guest reaches only the two public windows and the
/// advice region, none of which is in the ELF, so a program that wants to be
/// loaded there is not a program this VM can run — and enforcing it also
/// bounds what a hostile ELF can make the loader allocate.
pub mod guest_memory {
    /// First addressable byte, and where `_start` is placed.
    pub const RAM_ORIGIN: u32 = 0x0001_0000;

    /// Length of the region. `RAM_ORIGIN + RAM_LENGTH` is the initial `sp`,
    /// and lands on `0x8000_0000` — a window of just under 2 GiB.
    pub const RAM_LENGTH: u32 = 0x7FFF_0000;

    /// The top of RAM the stack keeps for itself. guest-sdk's
    /// allocator never hands out a block reaching into the last
    /// `STACK_RESERVE` bytes below `RAM_ORIGIN + RAM_LENGTH`, nor one above
    /// the live `sp`. 8 MiB: a native main thread's default stack on Linux and
    /// macOS, so a program whose call depth fits on the host fits here. Not
    /// part of the linker's map — `link.ld` has no symbol for it — but a
    /// number the SDK and its documents agree on.
    pub const STACK_RESERVE: u32 = 0x0080_0000;

    /// First byte of the **public input** window: the verifier-known input a
    /// statement is about (`docs/spec/public-values.md` §2).
    ///
    /// No RAM window family initializes an address in `[0, RAM_ORIGIN)`:
    /// `INIT_TEARDOWN` masks RAM window 0's rows below `2^14` with
    /// `V[ram_live]` and `ZERO_WINDOWS` never claims window 0
    /// (`docs/spec/memory.md` §3.3). The two public windows claim the
    /// **whole** of that range above `0x8000` — `2^12` words each, ending
    /// flush against `RAM_ORIGIN` — which is what makes that height the
    /// ceiling, and `[0, 0x8000)` stays a hole: a null dereference is a read
    /// of a tuple nothing wrote, and cannot balance.
    ///
    /// The address is not a free choice either. A window's first address is
    /// `4 * height * window`, so at [`family::PUBLIC_WINDOW_HEIGHT`] this is
    /// exactly window [`family::PUBLIC_INPUT_WINDOW`], and the address-space
    /// tag stays [`address_space::RAM`]. That is what keeps the three
    /// memory-op families' address decomposition, their load path and their
    /// store path untouched: to `mem_word` a public value is an ordinary RAM
    /// word.
    pub const PUBLIC_INPUT_ORIGIN: u32 = 0x0000_8000;

    /// First byte of the **public output** window — the journal — the next
    /// window up from [`PUBLIC_INPUT_ORIGIN`].
    ///
    /// At [`family::PUBLIC_WINDOW_HEIGHT`] = `2^12` the pair is windows 2 and
    /// 3 and ends flush against [`RAM_ORIGIN`]: the range below `RAM_ORIGIN`
    /// holds exactly two public windows and no more.
    pub const PUBLIC_OUTPUT_ORIGIN: u32 = 0x0000_C000;

    /// Bytes in each public window: `4 * family::PUBLIC_WINDOW_HEIGHT`.
    pub const PUBLIC_WINDOW_BYTES: u32 = 4 * crate::family::PUBLIC_WINDOW_HEIGHT;

    /// How many payload bytes a public window carries.
    ///
    /// Word 0 of each window is the payload's **byte length**, which is what
    /// makes a proof bind a byte string rather than merely its zero-padded
    /// word vector: without it `[1, 2, 3]` and `[1, 2, 3, 0]` fill the same
    /// window and a prover picks whichever suits it
    /// (`docs/spec/public-values.md` §3).
    pub const PUBLIC_PAYLOAD_BYTES: u32 = PUBLIC_WINDOW_BYTES - 4;

    /// First byte of the **advice** region: prover-supplied witness data,
    /// read with ordinary loads (`docs/spec/public-values.md` §6).
    ///
    /// It sits above RAM rather than inside it, so it competes with no heap
    /// and no stack. The address-space tag is [`address_space::RAM`] here
    /// too: what makes an advice word advice is that its window family's init
    /// column is bound to nothing, not a tag a load would have to name.
    pub const ADVICE_ORIGIN: u32 = 0x8000_0000;

    /// Words the advice region spans: `[ADVICE_ORIGIN, 2^32)`, 2 GiB.
    pub const ADVICE_WORDS: u32 = 1 << 29;
}

/// The guest ecall ABI: its numbers, in one place.
///
/// **A number is assigned once.** A program's identity binds its ABI, and
/// redefining a number does not fail loudly — it quietly makes an old program
/// compute something else — so numbers here are never reused, exactly like
/// `transcript_tags`. A *retired* number is struck out and never reassigned:
/// **63 and 64**, POSIX `read` and `write`, are retired
/// (`docs/spec/ecall-abi.md` §3).
///
/// An ecall carries its number in `a7`, its arguments in `a0`-`a5` and its
/// result in `a0`, with errors as a negated errno. **An Apogee guest is an
/// Apogee-SDK program, not a Linux one**: it has no file descriptors, no
/// streams and no I/O syscall at all. Its public input, its advice and its
/// journal are *memory the proof system binds* — ordinary loads and stores
/// against three fixed regions (`docs/spec/public-values.md`) — so the only
/// ecall a guest issues is [`EXIT`], which is exactly the provable one.
/// `docs/spec/ecall-abi.md` specifies the table.
pub mod ecall {
    /// Terminate. `a0` is the exit status; a nonzero status is a failed
    /// execution, which is still an execution and is reported rather than
    /// refused.
    ///
    /// The only ecall a guest may issue. Its number is 93, and nothing
    /// downstream reads any meaning into the value.
    pub const EXIT: u32 = 93;

    /// Linux `ENOSYS`. Every number but [`EXIT`] returns `-ENOSYS` in `a0`:
    /// a number nobody has assigned, or a retired one
    /// (`docs/spec/ecall-abi.md` §4). Such a call executes and cannot be
    /// proved.
    pub const ENOSYS: u32 = 38;
}

/// The memory argument's address spaces (`docs/spec/execution-trace.md` §2).
///
/// A memory query names one of these, and the tag is the `AS` term of the
/// compressed tuple `gamma_M + AS + alpha_addr*ADDR + ...`. The tags are
/// nonzero on purpose: `(REG, x0, ts 0, value 0)` is a real initial tuple, and
/// with `REG = 0` it would be the all-zero tuple — the same reason the decoded
/// tables pad with `MINUS_ONE` rather than 0. A tag is never reassigned.
pub mod address_space {
    /// The 32 registers. A query's address is the register index, `0..32`.
    pub const REG: u8 = 1;
    /// Guest RAM, word-granular. A query's address is the byte address of the
    /// 4-aligned word, so always a multiple of 4.
    pub const RAM: u8 = 2;
    /// The program counter: one address, `0`. Every cycle reads `pc` and
    /// writes `next_pc` here.
    pub const PC: u8 = 3;
}

/// The memory argument's clock and its own numbers.
///
/// Cycle `c` occupies timestamps `TS_STEP * c + delta` for the four in-cycle
/// slots `delta` in `0..TS_STEP`. Timestamp 0 is the initial write of every
/// address, so the first executed cycle is **cycle 1**: a cycle-0 pc query
/// would write at timestamp 0 and could not strictly follow the initial write
/// it reads. Every timestamp is below `2^TS_BITS`.
///
/// `docs/spec/execution-trace.md` §1 specifies the clock and
/// `docs/spec/memory.md` the rest.
pub mod memory {
    /// Timestamps per cycle, one per in-cycle slot.
    pub const TS_STEP: u64 = 4;
    /// The width of a timestamp, in bits.
    pub const TS_BITS: u32 = 38;

    /// The halting sentinel: the `next_pc` an exit row writes, and the pc's
    /// final value the verifier fixes. Odd, so no instruction's `next_pc` can
    /// be it, and below `guest_memory::RAM_ORIGIN`, so no decoded-table row
    /// claims it. `docs/spec/memory.md` §5.
    pub const HALT_PC: u32 = 1;

    /// A memory tuple's parts, in order: `AS`, added unweighted; then `ADDR`,
    /// `TS` and `VAL`, weighted by `α_addr`, `α_ts` and `α_val`.
    /// `docs/spec/memory.md` §1.
    pub const PART_AS: usize = 0;
    /// The tuple's address part.
    pub const PART_ADDR: usize = 1;
    /// The tuple's timestamp part.
    pub const PART_TS: usize = 2;
    /// The tuple's value part.
    pub const PART_VAL: usize = 3;

    /// The output-map position of every memory artifact's read root: the
    /// product of its read tuples. `docs/spec/memory.md` §1.
    pub const READ_ROOT: usize = 0;
    /// The output-map position of every memory artifact's write root.
    pub const WRITE_ROOT: usize = 1;

    /// Window 0's rows `y < 2^RAM_LIVE_BIT` lie below `RAM_ORIGIN`, which is
    /// `4 << RAM_LIVE_BIT`, and `ram_live` masks them. `docs/spec/memory.md`
    /// §3.1 and §3.3.
    pub const RAM_LIVE_BIT: u32 = 14;
}
