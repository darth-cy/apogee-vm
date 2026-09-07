#![no_std]
//! Frozen constants and tags for the whole workspace. Zero logic, forever.
//!
//! This crate holds constant items and doc comments and nothing else: no
//! functions, no traits, no macros, no tests. Guest-side code links it, so it
//! is `#![no_std]` and stays that way.
//!
//! Changing any value here is a protocol-version change.

/// Protocol version absorbed into every transcript before anything else.
///
/// Placeholder: bumped whenever a frozen protocol invariant changes.
pub const PROTOCOL_VERSION: u32 = 0;

/// BN254 scalar field modulus `p`, little-endian 64-bit limbs.
///
/// `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
/// `  = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`
///
/// This is Fr, the *scalar* field. The base field Fq is a different modulus.
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
// checks its BN254 Poseidon2 against. `RC3` is 64 rows of 3 constants. The 4
// initial full rounds (rows 0..4) and 4 terminal full rounds (rows 60..64) use
// all three lanes; the 56 partial rounds (rows 4..60) use lane 0 only, and
// upstream stores zero in lanes 1 and 2 of those rows.
//
// The three tables below are exactly the entries the permutation reads, split
// by the phase that reads them. `crates/transcript/tests/poseidon2.rs` checks all
// three — including that the lanes not stored here are zero upstream — against
// a committed dump of the full 64x3 table.
//
// Values are canonical (non-Montgomery) little-endian 64-bit limbs, per master
// rule 3; `field::Fr::from_canonical_limbs` converts them at compile time.
// One line per constant, so the table can be diffed against upstream by eye.
// ---------------------------------------------------------------------------

/// Round constants for the 4 initial full rounds: `RC3` rows 0..4, all lanes.
#[rustfmt::skip]
pub const POSEIDON2_RC3_INITIAL: [[[u64; 4]; 3]; 4] = [
    [
        [0x59a09a1a97052816, 0x7f8fcde48bb4c37a, 0x8bddd3a93f7804ef, 0x1d066a255517b7fd],
        [0xb7238547d32c1610, 0xb7c6fef31367b68e, 0xac3f089cebcc6120, 0x29daefb55f6f2dc6],
        [0x9e8b7ad7b0b4e1d1, 0x2572d76f08ec5c4f, 0x1ecbd88ad959d701, 0x1f2cb1624a78ee00],
    ],
    [
        [0xdb0672ded84f31e5, 0xb11f092a53bbc6e1, 0xbd77c0ed3d14aa27, 0x0aad2e79f15735f2],
        [0x091ccf1595b43f28, 0x37028a98f1dece66, 0xd6f661dd4094375f, 0x2252624f8617738c],
        [0xd49f4f2c9018d735, 0x91c20626524b2b87, 0x5a65a84a291da1ff, 0x1a24913a928b3848],
    ],
    [
        [0x4fd6dae1508fc47a, 0x0a41515ddff497b1, 0x7bfc427b5f11ebb1, 0x22fc468f1759b74d],
        [0xefd65515617f6e4d, 0xe61956ff0b4121d5, 0x9cd026e9c9ca107a, 0x1059ca787f1f89ed],
        [0xa45cbbfae8b981ce, 0x2123011f0bf6f155, 0xf61f3536d877de98, 0x02be9473358461d8],
    ],
    [
        [0xa1ff3a441a5084a4, 0xaba9b669ac5b8736, 0x2778a749c82ed623, 0x0ec96c8e32962d46],
        [0x48fb2e4d814df57e, 0x5a47a7cdb8c99f96, 0x5442d9553c45fa3f, 0x292f906e07367740],
        [0x0c63f0b2ffe5657e, 0xcc611160a394ea46, 0x26c11b9a0f5e39a5, 0x274982444157b867],
    ],
];

/// Round constants for the 56 partial rounds: `RC3` rows 4..60, lane 0 only.
#[rustfmt::skip]
pub const POSEIDON2_RC3_INTERNAL: [[u64; 4]; 56] = [
    [0x499573f23597d4b5, 0xcedd192f47308731, 0xb63e1855bff015b8, 0x1a1d063e54b1e764],
    [0xb91b002c5b257c37, 0x08235dccc1aa3793, 0x839d109562590637, 0x26abc66f3fdf8e68],
    [0x0b3c2b12ff4d7be8, 0x0754427aabca92a7, 0x81a578cfed5aed37, 0x0c7c64a9d8873853],
    [0xedd383831354b495, 0xba2ebac30dc386b0, 0x9e17f0b6d08b2d1e, 0x1cf5998769e9fab7],
    [0x7aba0b97e66b0109, 0x19828764a9669bc1, 0x564ca60461e9e08b, 0x0f5e3a8566be31b7],
    [0x42bf3d7a531c976e, 0xf359a53a180b7d4b, 0x95e60e4db0794a01, 0x18df6a9d19ea90d8],
    [0x4e324055fa3123dc, 0xd0ea1d3a3b9d25ef, 0x6e4b782c3c6e601a, 0x04f7bf2c5c0538ac],
    [0xe55d54628b89ebe6, 0xe770c0584aa2328c, 0x3c40058523748531, 0x29c76ce22255206e],
    [0x00e0e945dbc5ff15, 0x65b1b8e9c6108dbe, 0xc053659ab4347f5d, 0x198d425a45b78e85],
    [0x49d3a9a90c3fdf74, 0xa7ff7f6878b3c49d, 0x6af3cc79c598a1da, 0x25ee27ab6296cd5e],
    [0xc0f88687a96d1381, 0x05845d7d0c55b1b2, 0x24561001c0b6eb15, 0x138ea8e0af41a1e0],
    [0x4013370a01d95687, 0x42851b5b9811f2ca, 0xf6e7c2cba2eefd0e, 0x306197fb3fab671e],
    [0x86419eaf00e8f620, 0x21db7565e5b42504, 0x2b66f0b4894d4f1a, 0x1a0c7d52dc32a443],
    [0xaa52997da2c54a9f, 0xebfbe5f55163cd6c, 0x3ff86a8e5c8bdfcc, 0x2b46b418de80915f],
    [0xfb46e312b5829f64, 0x613a1af5db48e05b, 0x01f8b777b9673af9, 0x12d3e0dc00858737],
    [0xba338a5cb19b3a1f, 0xfb2bf768230f648d, 0x70f5002ed21d089f, 0x263390cf74dc3a88],
    [0x7d543db52b003dcd, 0xf8abb5af40f96f1d, 0x0ac884b4ca607ad0, 0x0a14f33a5fe668a6],
    [0xd847df829bc683b9, 0x27be3a4f01171a1d, 0x1a5e86509d68b2da, 0x28ead9c586513eab],
    [0xea16cda6e1a7416c, 0x888f0ea1abe71cff, 0x0972031f1bdb2ac9, 0x1c6ab1c328c3c643],
    [0x32346015c5b42c94, 0x4f6decd608cb98a9, 0x2b2500239f7f8de0, 0x1fc7e71bc0b81979],
    [0xe6dd85b93a0ddaa8, 0xc0c1e197c952650e, 0xe380e0d860298f17, 0x03e107eb3a42b2ec],
    [0x454505f6941d78cd, 0x46452ca57c08697f, 0x69c0d52bf88b772c, 0x2d354a251f381a46],
    [0xd14b4606826f794b, 0x522551d61606eda3, 0xf687ef14bc566d1c, 0x094af88ab05d94ba],
    [0xd52b2d249d1396f7, 0xe1ab5b6f2e3195a9, 0x19bcaeabf02f8ca5, 0x19705b783bf3d2dc],
    [0x60cef6852271200e, 0x8723b16b7d740a3e, 0x1fcc33fee54fc5b2, 0x09bf4acc3a8bce3f],
    [0x543a073f3f3b5e4e, 0x3413732f301f7058, 0x50f83c0c8fab6284, 0x1803f8200db6013c],
    [0xd41f7fef2faf3e5c, 0xbf6fb02d4454c0ad, 0x30595b160b8d1f38, 0x0f80afb5046244de],
    [0x7dc3f98219529d78, 0xabcfcf643f4a6fea, 0xd77f0088c1cfc964, 0x126ee1f8504f15c3],
    [0xef86f991d7d0a591, 0x0ffb4ee63175ddf8, 0x69bfb3d919552ca1, 0x23c203d10cfcc60f],
    [0x7c5a339f7744fb94, 0x3dec1ee4eec2cf74, 0xec0d09705fa3a630, 0x2a2ae15d8b143709],
    [0xb6b5d89081970b2b, 0xc3d3b3006cb461bb, 0x47e5c381ab6343ec, 0x07b60dee586ed6ef],
    [0x132cfe583c9311bd, 0x8a98a320baa7d152, 0x885d95c494c1ae3d, 0x27316b559be3edfd],
    [0x2f5f9af0c0342e76, 0xef834cc2a743ed66, 0xd8937cb2d3f84311, 0x1d5c49ba157c32b8],
    [0x7c24bd5940968488, 0x09c01bf6979938f6, 0x332774e0b850b5ec, 0x2f8b124e78163b2f],
    [0x665f75260113b3d5, 0x1d4cba6554e51d84, 0xdc5b7aa09a9ce21b, 0x1e6843a5457416b6],
    [0x1f5bc79f21641d4b, 0xa68daf9ac6a189ab, 0x5fca25c9929c8ad9, 0x11cdf00a35f650c5],
    [0xe82b5b9b7eb560bc, 0x608b2815c77355b7, 0x2ef36e588158d6d4, 0x21632de3d3bbc5e4],
    [0x49d7b5c51c18498a, 0x255ae48ef2a329e4, 0x97b27025fbd245e0, 0x0de625758452efbd],
    [0x9b09546ba0838098, 0xdd9e1e1c6f0fb6b0, 0xe2febfd4d976cc01, 0x2ad253c053e75213],
    [0xd35702e38d60b077, 0x3dd49cdd13c813b7, 0x6ec7681ec39b3be9, 0x1d6b169ed63872dc],
    [0xc3a54e706cfef7fe, 0x0be3ea70a24d5568, 0xb9127c4941b67fed, 0x1660b740a143664b],
    [0x96a29f10376ccbfe, 0xceacdddb12cf8790, 0x114f4ca2deef76e0, 0x0065a92d1de81f34],
    [0xcf30d50a5871040d, 0x353ebe2ccbc4869b, 0x7367f823da7d672c, 0x1f11f06520253598],
    [0x110852d17df0693e, 0x3bd1d1a39b6759ba, 0xb437ce7b14a2c3dd, 0x26596f5c5dd5a5d1],
    [0x6743db15af91860f, 0x8539c4163a5f1e70, 0x7bf3056efcf8b6d3, 0x16f49bc727e45a2f],
    [0xe1a4e7438dd39e5f, 0x568feaf7ea8b3dc5, 0x9954175efb331bf4, 0x1abe1deb45b3e311],
    [0x020d34aea15fba59, 0x9f5db92aaec5f102, 0xd8993a74ca548b77, 0x0e426ccab66984d1],
    [0xa841924303f6a6c6, 0x0071684b902d534f, 0x4933bd1942053f1f, 0x0e7c30c2e2e8957f],
    [0x4c76e1f31d3fc69d, 0x6166ded6e3528ead, 0x1622708fc7edff1d, 0x0812a017ca92cf0a],
    [0x2e276b47cf010d54, 0x68afe5026edd7a9c, 0xbba949d1db960400, 0x21a5ade3df2bc1b5],
    [0x72b1a5233f8749ce, 0xbd101945f50e5afe, 0xad711bf1a058c6c6, 0x01f3035463816c84],
    [0x4dcaa82b0f0c1c8b, 0x8bf2f9398dbd0fdf, 0x028c2aafc2d06a5e, 0x0b115572f038c0e2],
    [0x3460613b6ef59e2f, 0x27fc24db42bc910a, 0xf0ef255543f50d2e, 0x1c38ec0b99b62fd4],
    [0xb1d0b254d880c53e, 0x2f5d314606a297d4, 0x425c3ff1f4ac737b, 0x1c89c6d9666272e8],
    [0x8b71e2311bb88f8f, 0x21ad4880097a5eb3, 0xf6d44008ae4c042a, 0x03326e643580356b],
    [0x5bdde2299910a4c9, 0x50f27a6434b5dceb, 0x67cee9ea0e51e3ad, 0x268076b0054fb73f],
];

/// Round constants for the 4 terminal full rounds: `RC3` rows 60..64, all lanes.
#[rustfmt::skip]
pub const POSEIDON2_RC3_TERMINAL: [[[u64; 4]; 3]; 4] = [
    [
        [0x78d04aa6f8747ad0, 0x5da18ea9d8e4f101, 0x626ed93491bda32e, 0x1acd63c67fbc9ab1],
        [0xca8c86cd2a28b5a5, 0x1bf93375e2323ec3, 0xc4e3144be58ef690, 0x19f8a5d670e8ab66],
        [0xe1cfbb5f7b9b6893, 0x068193ea51f6c92a, 0x6efa40d2df10a011, 0x1c0dc443519ad7a8],
    ],
    [
        [0x180e4c3224987d3d, 0xfbeab33cb4f6a2c4, 0x50fe7190e421dc19, 0x14b39e7aa4068dbe],
        [0xafb1e35e28b0795e, 0xb820fc519f01f021, 0x8f28c63ea6c561b7, 0x1d449b71bd826ec5],
        [0x76524dc0a9e987fc, 0x89de141689d12522, 0x60fa97fe60fe9d8e, 0x1ea2c9a89baaddbb],
    ],
    [
        [0x134d5cefdb3c7ff1, 0x591f9a46a0e9c058, 0xb57e9c1c3d6a2bd7, 0x0478d66d43535a8c],
        [0x1cde5e4a7b00bebe, 0x662e26ad86c400b2, 0xf608f3b2717f9cd2, 0x19272db71eece6a6],
        [0x039be846af134166, 0xb2dd1bd66a87ef75, 0xc749c746f09208ab, 0x14226537335cab33],
    ],
    [
        [0xf912f44961f9a9ce, 0xb21c21e4a1c2e823, 0x9dfe38c0d976a088, 0x01fd6af15956294f],
        [0x5ad8518d4e5f2a57, 0xaee2e62ed229ba5a, 0x7bca190b8b2cab1a, 0x18e5abedd626ec30],
        [0x0e2d54dc1c84fda6, 0x97c021a3a409926d, 0xabbdffa6d3b35e32, 0x0fc1bbceba0590f5],
    ],
];

/// Domain-separation tags for the Poseidon2 duplex transcript.
///
/// Sequential `u64`, assigned once and never renumbered: a value here is part
/// of the absorbed stream, so changing one is a protocol-version change. Later
/// stages append to this table; they never renumber or reuse.
///
/// `0` is deliberately not a tag, so an uninitialised tag can never be a valid
/// message.
///
/// **One tag, one message kind.** The typed layer frames every message as
/// `tag, length, payload...` and nothing more, so injectivity of the absorbed
/// stream rests on each tag naming exactly one kind of message — scalars *or*
/// bytes *or* a challenge, never two. Each constant below records its kind.
/// Adding a tag is free; reusing one across kinds is a soundness bug. See
/// `docs/spec/transcript.md` section 8.
pub mod transcript_tags {
    /// Scalars. The protocol suite and version preamble, absorbed first in
    /// every transcript, before any other message.
    pub const PROTOCOL_SUITE: u64 = 1;

    /// Bytes. The statement's public inputs / public I/O.
    pub const PUBLIC_INPUTS: u64 = 2;

    /// Scalars. A commitment, as the Fr limbs of its G1 points.
    pub const COMMITMENT: u64 = 3;

    /// Scalars. One sumcheck round polynomial's coefficients.
    pub const SUMCHECK_ROUND: u64 = 4;

    /// Challenge. The sumcheck challenge for the round just absorbed.
    pub const SUMCHECK_CHALLENGE: u64 = 5;

    /// Scalars. A claimed evaluation of a committed or virtual polynomial.
    pub const EVALUATION_CLAIM: u64 = 6;

    /// Scalars. Mercury opening-proof material.
    pub const PCS_OPENING: u64 = 7;
}
