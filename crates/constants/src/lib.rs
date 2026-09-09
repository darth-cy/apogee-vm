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
// Fq, the BN254 base field, and the curve/tower constants that live over it.
//
// Fq is where curve coordinates live; Fr is where everything arithmetized in
// the VM lives. Their top two limbs are identical — the two moduli agree in
// their top 128 bits and differ only below — so they are easy to confuse by eye
// and the tests re-derive both.
//
// The Montgomery machinery constants below are limb arrays, exactly as their
// Fr counterparts are. The tower and curve parameters are hex string literals
// read big-endian by `curve::Fq::from_hex`, the same one accepted spelling
// `field::Fr::from_hex` defines, so each one diffs against EIP-197 and
// arkworks-bn254 by eye.
// ---------------------------------------------------------------------------

/// BN254 base field modulus `q`, little-endian 64-bit limbs.
///
/// `q = 21888242871839275222246405745257275088696311157297823662689037894645226208583`
/// `  = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47`
///
/// `q = 3 mod 4`, which is what makes a square root one exponentiation.
pub const FQ_MODULUS: [u64; 4] = [
    0x3c20_8c16_d87c_fd47,
    0x9781_6a91_6871_ca8d,
    0xb850_45b6_8181_585d,
    0x3064_4e72_e131_a029,
];

/// `q - 2`, little-endian 64-bit limbs: the Fermat exponent for inversion.
pub const FQ_MODULUS_MINUS_TWO: [u64; 4] = [
    0x3c20_8c16_d87c_fd45,
    0x9781_6a91_6871_ca8d,
    0xb850_45b6_8181_585d,
    0x3064_4e72_e131_a029,
];

/// `(q + 1) / 4`, little-endian 64-bit limbs: the square-root exponent.
///
/// For `q = 3 mod 4`, `x^((q+1)/4)` is a square root of `x` whenever `x` has
/// one. It is an integer because `q + 1 = 0 mod 4`.
pub const FQ_MODULUS_PLUS_ONE_DIV_FOUR: [u64; 4] = [
    0x4f08_2305_b61f_3f52,
    0x65e0_5aa4_5a1c_72a3,
    0x6e14_116d_a060_5617,
    0x0c19_139c_b84c_680a,
];

/// Montgomery radix `R = 2^256 mod q`, little-endian 64-bit limbs.
///
/// `R` is also the Montgomery representation of `1`.
pub const FQ_R: [u64; 4] = [
    0xd35d_438d_c58f_0d9d,
    0x0a78_eb28_f5c7_0b3d,
    0x666e_a36f_7879_462c,
    0x0e0a_77c1_9a07_df2f,
];

/// `R^2 mod q`, little-endian 64-bit limbs: converts a canonical value into
/// Montgomery form via one Montgomery multiplication.
pub const FQ_R2: [u64; 4] = [
    0xf32c_fc5b_538a_fa89,
    0xb5e7_1911_d445_01fb,
    0x47ab_1eff_0a41_7ff6,
    0x06d8_9f71_cab8_351f,
];

/// `-q^{-1} mod 2^64`, the per-limb Montgomery reduction multiplier.
pub const FQ_INV: u64 = 0x87d2_0782_e486_6389;

/// The Fq2 nonresidue: `Fq2 = Fq[u]/(u^2 - FQ2_NONRESIDUE)`, so `u^2 = -1`.
///
/// This is `q - 1`. `-1` is a nonresidue exactly because `q = 3 mod 4`, and
/// that single fact is what makes the Fq2 square root a two-branch closed form
/// (see `curve::Fq2::sqrt`). Implementations multiply by it by negating, so the
/// value appears here as the frozen definition and in `curve`'s constants test
/// as the thing negation is checked against.
pub const FQ2_NONRESIDUE: &str =
    "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46";

/// `xi = 9 + u`, real part: the nonresidue that builds Fq6 over Fq2.
///
/// `curve::Fq2::mul_by_nonresidue` multiplies by it. The Fq6 and Fq12 layers
/// that consume it arrive with the pairing in the next stage; the G2 curve
/// constant `3/xi` below already depends on it.
pub const FQ6_NONRESIDUE_C0: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000009";

/// `xi = 9 + u`, `u` part.
pub const FQ6_NONRESIDUE_C1: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000001";

/// G1's curve constant: `E/Fq: y^2 = x^3 + 3`.
pub const G1_B: &str = "0x0000000000000000000000000000000000000000000000000000000000000003";

/// G2's curve constant `3/xi = 3/(9+u)`, real part.
///
/// `E'/Fq2: y^2 = x^3 + 3/xi` is the D-type sextic twist, the curve EIP-197's
/// G2 generator lies on.
pub const G2_B_C0: &str = "0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5";

/// G2's curve constant `3/xi = 3/(9+u)`, `u` part.
pub const G2_B_C1: &str = "0x009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2";

/// The standard G1 generator, `x`. The generator is `(1, 2)`.
pub const G1_GENERATOR_X: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000001";

/// The standard G1 generator, `y`.
pub const G1_GENERATOR_Y: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000002";

/// The standard G2 generator, `x` real part. EIP-197's G2, coordinate for
/// coordinate.
pub const G2_GENERATOR_X_C0: &str =
    "0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed";

/// The standard G2 generator, `x` `u` part.
pub const G2_GENERATOR_X_C1: &str =
    "0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2";

/// The standard G2 generator, `y` real part.
pub const G2_GENERATOR_Y_C0: &str =
    "0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

/// The standard G2 generator, `y` `u` part.
pub const G2_GENERATOR_Y_C1: &str =
    "0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b";

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
// `crates/transcript/tests/poseidon2.rs` checks all three — including that the
// lanes not stored here are zero upstream — against a committed dump of the
// full 64x3 table, so the transcription is verified rather than trusted.
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

    /// Challenge. Every challenge a sumcheck draws: first the `n` eq-randomizers
    /// `r` that fix the zerocheck's equality polynomial, then the per-round
    /// challenge for the round just absorbed. One tag, one kind; the two roles
    /// are separated by their fixed position in the transcript script, not by
    /// their tag.
    pub const SUMCHECK_CHALLENGE: u64 = 5;

    /// Scalars. A claimed evaluation of a committed or virtual polynomial.
    pub const EVALUATION_CLAIM: u64 = 6;

    /// Scalars. Mercury opening-proof material.
    pub const PCS_OPENING: u64 = 7;

    /// Scalars. The single squeezed `Fr` that binds a witness's columns to the
    /// transcript before any challenge is drawn over them. The same tag frames
    /// the messages inside the separate sponge that produces it; see
    /// `crates/sumcheck`.
    pub const WITNESS_DIGEST: u64 = 8;

    /// Scalars. A sumcheck's `final_evals`: the claimed value of every input
    /// polynomial at the fully bound point, absorbed before any later challenge.
    pub const SUMCHECK_FINAL_EVALS: u64 = 9;
}
