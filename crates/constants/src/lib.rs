#![no_std]
//! Frozen constants and tags for the whole workspace. Zero logic, forever.
//!
//! This crate holds constant items and doc comments and nothing else: no
//! functions, no traits, no macros, no tests. Guest-side code links it, so it
//! is `#![no_std]` and stays that way.
//!
//! From the first registered program identity on, changing any value here is
//! a protocol-version change.

/// Protocol version absorbed into every transcript before anything else.
///
/// Placeholder, 0, until the first program identity is registered; from then
/// on it is bumped whenever a frozen protocol invariant changes. S12 and S14
/// changed frozen values without a bump, by the owner's decision
/// (`docs/handoff/S14-multiset.md`).
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

/// The 2-adicity of `p - 1`: `p - 1 = 2^28 * c` with `c` odd.
///
/// The ceiling on every radix-2 FFT this protocol can run. Mercury's opening
/// needs a `2b`-th root of unity for `b = sqrt(n)`, so it caps `n` at `2^54` —
/// far above the trace-height menu, and above what any SRS this repository
/// reads can commit to.
pub const FR_TWO_ADICITY: u32 = 28;

/// A generator of the order-`2^FR_TWO_ADICITY` subgroup of `Fr^*`.
///
/// `5^((p - 1) / 2^28) mod p`, where `5` is the smallest multiplicative
/// generator of `Fr^*`. Squaring it `28 - k` times gives the `2^k`-th root of
/// unity an FFT of size `2^k` needs. Re-derived from `5` and checked for exact
/// order in `crates/pcs/src/fft.rs`'s unit tests rather than trusted.
pub const FR_TWO_ADIC_ROOT_OF_UNITY: &str =
    "0x2a3c09f0a58a7e8500e0a7eb8ef62abc402d111e41112ed49bd61b6e725b19f0";

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
/// `curve::Fq2::mul_by_nonresidue` multiplies by it, `curve::Fq6` is built over
/// it, and every Frobenius table further down is one of its powers. The G2
/// curve constant `3/xi` below depends on it too.
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
// The pairing: the Fq6/Fq12 Frobenius tables, the twist Frobenius, the ate
// loop and the final exponentiation.
//
// The tower `curve::pairing` completes is
//
//     Fq2  = Fq[u]/(u^2 + 1)
//     Fq6  = Fq2[v]/(v^3 - xi),   xi = 9 + u   (FQ6_NONRESIDUE_C0/_C1 above)
//     Fq12 = Fq6[w]/(w^2 - v)
//
// Every table below is a power of `xi`, so each entry is re-derivable from a
// single number and each is re-derived in `crates/curve/tests/constants_check.rs`
// rather than trusted. They are hex string literals in the one accepted source
// spelling, read big-endian by `curve::Fq::from_hex`, so they diff against
// arkworks-bn254's own tables by eye.
// ---------------------------------------------------------------------------

/// `xi^((q^i - 1)/3)` for `i` in `0..6`, as `[c0, c1]` of an `Fq2`.
///
/// The `v` coefficient's Frobenius twist: `(a1 v)^(q^i) = a1^(q^i) * xi^((q^i-1)/3) * v`,
/// because `v^3 = xi` forces `v^(q^i) = xi^((q^i-1)/3) * v`. Index 0 is one.
pub const FQ6_FROBENIUS_C1: [[&str; 2]; 6] = [
    [
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x2fb347984f7911f74c0bec3cf559b143b78cc310c2c3330c99e39557176f553d",
        "0x16c9e55061ebae204ba4cc8bd75a079432ae2a1d0b7c9dce1665d51c640fcba2",
    ],
    [
        "0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x0856e078b755ef0abaff1c77959f25ac805ffd3d5d6942d37b746ee87bdcfb6d",
        "0x04f1de41b3d1766fa9f30e6dec26094f0fdf31bf98ff2631380cab2baaa586de",
    ],
    [
        "0x000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x28be74d4bb943f51699582b87809d9caf71614d4b0b71f3a62e913ee1dada9e4",
        "0x14a88ae0cb747b99c2b86abcbe01477a54f40eb4c3f6068dedae0bcec9c7aac7",
    ],
];

/// `xi^((2 q^i - 2)/3)` for `i` in `0..6`, as `[c0, c1]` of an `Fq2`.
///
/// The `v^2` coefficient's twist, and the square of [`FQ6_FROBENIUS_C1`] entry
/// for entry — which is asserted rather than assumed.
pub const FQ6_FROBENIUS_C2: [[&str; 2]; 6] = [
    [
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x05b54f5e64eea80180f3c0b75a181e84d33365f7be94ec72848a1f55921ea762",
        "0x2c145edbe7fd8aee9f3a80b03b0b1c923685d2ea1bdec763c13b4711cd2b8126",
    ],
    [
        "0x000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x0bc58c6611c08dab19bee0f7b5b2444ee633094575b06bcb0e1a92bc3ccbf066",
        "0x23d5e999e1910a12feb0f6ef0cd21d04a44a9e08737f96e55fe3ed9d730c239f",
    ],
    [
        "0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x1ee972ae6a826a7d1d9da40771b6f589de1afb54342c724fa97bda050992657f",
        "0x10de546ff8d4ab51d2b513cdbb25772454326430418536d15721e37e70c255c9",
    ],
];

/// `xi^((q^i - 1)/6)` for `i` in `0..12`, as `[c0, c1]` of an `Fq2`.
///
/// The `w` coefficient's Frobenius twist: `w^2 = v` and `v^3 = xi` give
/// `w^6 = xi`, so `w^(q^i) = xi^((q^i-1)/6) * w`. Index 0 is one.
pub const FQ12_FROBENIUS_C1: [[&str; 2]; 12] = [
    [
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x1284b71c2865a7dfe8b99fdd76e68b605c521e08292f2176d60b35dadcc9e470",
        "0x246996f3b4fae7e6a6327cfe12150b8e747992778eeec7e5ca5cf05f80f362ac",
    ],
    [
        "0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd49",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x19dc81cfcc82e4bbefe9608cd0acaa90894cb38dbe55d24ae86f7d391ed4a67f",
        "0x00abf8b60be77d7306cbeee33576139d7f03a5e397d439ec7694aa2bf4c0c101",
    ],
    [
        "0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x0757cab3a41d3cdc072fc0af59c61f302cfa95859526b0d41264475e420ac20f",
        "0x0ca6b035381e35b618e9b79ba4e2606ca20b7dfd71573c93e85845e34c4a5b9c",
    ],
    [
        "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x1ddf9756b8cbf849cf96a5d90a9accfd3b2f4c893f42a9166615563bfbb318d7",
        "0x0bfab77f2c36b843121dc8b86f6c4ccf2307d819d98302a771c39bb757899a9b",
    ],
    [
        "0x000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x1687cca314aebb6dc866e529b0d4adcd0e34b703aa1bf84253b10eddb9a856c8",
        "0x2fb855bcd54a22b6b18456d34c0b44c0187dc4add09d90a0c58be1eae3bc3c46",
    ],
    [
        "0x000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177ffffff",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    [
        "0x290c83bf3d14634db120850727bb392d6a86d50bd34b19b929bc44b896723b38",
        "0x23bd9e3da9136a739f668e1adc9ef7f0f575ec93f71a8df953c846338c32a1ab",
    ],
];

/// `xi^((q - 1)/3)`: the `x` factor of the untwist-Frobenius-twist map on G2.
///
/// The Miller loop's two closing steps add `psi(Q)` and `-psi(psi(Q))` to the
/// accumulator, where `psi(x, y) = (x^q * TWIST_FROBENIUS_X, y^q * TWIST_FROBENIUS_Y)`
/// and `^q` on an `Fq2` is conjugation. This is [`FQ6_FROBENIUS_C1`]`[1]`, and
/// the constants test asserts that.
pub const TWIST_FROBENIUS_X: [&str; 2] = [
    "0x2fb347984f7911f74c0bec3cf559b143b78cc310c2c3330c99e39557176f553d",
    "0x16c9e55061ebae204ba4cc8bd75a079432ae2a1d0b7c9dce1665d51c640fcba2",
];

/// `xi^((q - 1)/2)`: the `y` factor of the same map, and the cube of
/// [`FQ12_FROBENIUS_C1`]`[1]`.
pub const TWIST_FROBENIUS_Y: [&str; 2] = [
    "0x063cf305489af5dcdc5ec698b6e2f9b9dbaae0eda9c95998dc54014671a0135a",
    "0x07c03cbcac41049a0704b5a7ec796f2b21807dc98fa25bd282d37f632623b0e3",
];

/// The BN parameter `x`, positive, with
/// `q = 36x^4 + 36x^3 + 24x^2 + 6x + 1` and `r = 36x^4 + 36x^3 + 18x^2 + 6x + 1`.
///
/// Both identities are checked in `crates/curve/tests/constants_check.rs`, so
/// this one number pins both moduli.
pub const BN_PARAMETER_X: u64 = 4965661367192848881;

/// The non-adjacent form of `6x + 2 = 29793968203157093288`, digits
/// least-significant first, each in `{-1, 0, 1}`.
///
/// The optimal ate pairing's Miller loop runs over this: `sum_i d_i 2^i` is
/// `6x + 2`, no two adjacent digits are nonzero, and the leading digit is the
/// one at index 65, consumed by initialising the accumulator to `Q`. All four
/// properties are asserted in `crates/curve/tests/constants_check.rs`.
#[rustfmt::skip]
pub const ATE_LOOP_NAF: [i8; 66] = [
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1,
    0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0,
    0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 0,
    1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0,
    -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0,
    -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 1,
];

/// `|lambda_0| = 36x^3 + 30x^2 + 18x + 2`, little-endian 64-bit limbs.
///
/// The final exponentiation's hard part raises to `d = (q^4 - q^2 + 1)/r`,
/// which in base `q` is `d = lambda_0 + lambda_1 q + lambda_2 q^2 + q^3` with
/// `lambda_0` and `lambda_1` **negative**. The magnitudes are stored here and
/// the sign is applied by conjugation, which is inversion in the cyclotomic
/// subgroup the easy part lands in. Reference for the decomposition: Scott,
/// Benger, Charlemagne, Dominguez Perez and Kachisa, *On the final
/// exponentiation for calculating pairings on ordinary elliptic curves*,
/// ePrint 2008/490 — the procedure Beuchat et al. ePrint 2010/354 section 4.2
/// follows. `crates/curve/tests/constants_check.rs` checks the recomposition
/// against `(q^4 - q^2 + 1)/r` as integers.
pub const FINAL_EXP_LAMBDA_0: [u64; 4] = [
    0xb687_f7e0_0783_02b6,
    0x3a97_459a_6afe_5ea2,
    0xb3c4_d79d_41a9_1759,
    0x0000_0000_0000_0000,
];

/// `|lambda_1| = 36x^3 + 18x^2 + 12x - 1`, little-endian 64-bit limbs, negative.
pub const FINAL_EXP_LAMBDA_1: [u64; 4] = [
    0x2891_5aa0_7812_cc81,
    0x5bfc_4108_8d8d_aaa9,
    0xb3c4_d79d_41a9_1758,
    0x0000_0000_0000_0000,
];

/// `lambda_2 = 6x^2 + 1`, little-endian 64-bit limbs, positive.
pub const FINAL_EXP_LAMBDA_2: [u64; 4] = [
    0xf83e_9682_e87c_fd47,
    0x6f4d_8248_eeb8_59fb,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
];

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

/// The `Fr` limb a point at infinity absorbs in place of each of its four
/// coordinate limbs.
///
/// `2^128`. A transcript absorbs an affine G1 point as four `Fr` limbs —
/// `x` low, `x` high, `y` low, `y` high — each the 128-bit halves of a
/// canonical `Fq` coordinate, so **every limb of every real point is strictly
/// below `2^128`**. `2^128` is therefore the smallest value no limb can take,
/// and the sentinel cannot collide with any point, on the curve or off it.
/// The non-collision is a fact about the split, not about the curve equation.
///
/// Spelled the way every frozen `Fr` literal in this crate is: `0x` plus 64
/// lowercase big-endian hex digits, read by `field::Fr::from_hex`.
/// `docs/spec/mercury.md` §4 is normative.
pub const G1_INFINITY_SENTINEL: &str =
    "0x0000000000000000000000000000000100000000000000000000000000000000";

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
    /// Scalars. The protocol suite and version preamble, `[PROTOCOL_VERSION]`:
    /// the first message of the statement's global transcript
    /// (`docs/spec/shard-proof.md` §2, G1). The shard transcripts and the
    /// identity, I/O and SRS-digest sponges open with their own tags instead.
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

    /// Scalars. A Mercury opening's instance size: the single element `n`, the
    /// number of evaluations of the polynomial being opened. Absorbed first,
    /// before the commitment. `docs/spec/mercury.md` §5.
    pub const MERCURY_INSTANCE: u64 = 10;

    /// Challenge. Mercury's fold point `alpha`, drawn after `h` is absorbed.
    pub const MERCURY_ALPHA: u64 = 11;

    /// Challenge. Mercury's inner-product batching challenge `gamma`, drawn
    /// after `q` and `g` are absorbed.
    pub const MERCURY_GAMMA: u64 = 12;

    /// Challenge. Mercury's evaluation point `z`, drawn after `s` and `d` are
    /// absorbed. Resampled under this same tag while it is zero, so `1/z`
    /// exists; `docs/spec/mercury.md` §7.
    pub const MERCURY_Z: u64 = 13;

    /// Challenge. The BDFG20 opening-batch challenge, drawn after every
    /// polynomial being batched has been committed and every claimed value
    /// absorbed.
    pub const BDFG_BATCH: u64 = 14;

    /// Challenge. The BDFG20 second evaluation point `z'`, drawn after its
    /// first proof element `W` is absorbed.
    pub const BDFG_POINT: u64 = 15;

    /// Challenge. The RLC that merges a verifier's two pairing relations into
    /// one. Drawn last, after every proof element is absorbed.
    pub const PAIRING_MERGE: u64 = 16;

    /// Challenge. The RLC that batches `k` same-size column commitments opened
    /// at one point into a single Mercury instance. Drawn after every
    /// commitment and every claimed value is absorbed, and never before.
    /// `docs/spec/mercury.md` section 11.
    pub const MERCURY_BATCH: u64 = 17;

    /// Scalars. The words of an accumulator entry list, absorbed by the
    /// separate sponge that produces the accumulator digest. The squeeze that
    /// ends that sponge is a raw `sample`, **not** a `challenge_scalar`, for
    /// the same reason `WITNESS_DIGEST`'s is: a challenge under this tag would
    /// be one tag in two kinds. `docs/spec/accumulator.md` section 5.
    pub const ACCUMULATOR_DIGEST: u64 = 18;

    /// Challenge. The RLC weight a discharge gives each deferred check, drawn
    /// from a sponge seeded with the accumulator digest so that it is a
    /// deterministic function of the entry list and nothing else.
    /// `docs/spec/accumulator.md` section 6.
    pub const ACCUMULATOR_MERGE: u64 = 19;

    /// Bytes. The guest's fd 0 stream inside the public I/O digest's own
    /// sponge. Absorbed first, before the output stream, which is what
    /// domain-separates the two. `docs/spec/ecall-abi.md` section 6.
    pub const PUBLIC_INPUT_STREAM: u64 = 20;

    /// Bytes. The guest's fd 1 stream inside the public I/O digest's own
    /// sponge, absorbed second. Distinct from [`PUBLIC_INPUT_STREAM`] so that
    /// swapping two unequal streams changes the digest.
    /// `docs/spec/ecall-abi.md` section 6.
    pub const PUBLIC_OUTPUT_STREAM: u64 = 21;

    /// Scalars. The first message of the program-identity sponge: the single
    /// element `code version`. It is what opens that sponge, so the identity
    /// is domain-separated from every other digest in the protocol.
    /// `crates/program/CLAUDE.md`. Since S16 also the global transcript's G6
    /// message, `[identity]` (`docs/spec/shard-proof.md` §2).
    pub const PROGRAM_IDENTITY: u64 = 22;

    /// Scalars. The static `VmConfig`: the family ids in ascending order, then
    /// their heights in the same order, then `bytecode_size_words`. The first
    /// of the statement descriptor's three messages, and the second message of
    /// the program-identity sponge.
    pub const VM_CONFIG: u64 = 23;

    /// Scalars. The per-proof shard count of every family in the `VmConfig`,
    /// in the same ascending order. The second of the statement descriptor's
    /// three messages, always absorbed immediately after the [`VM_CONFIG`]
    /// message it counts shards for and before [`MEMORY_WINDOWS`].
    pub const SHARD_COUNTS: u64 = 24;

    /// Scalars. A GKR circuit's claimed output tables, output-map order, as
    /// one message, absorbed before the top-layer point is drawn so that no
    /// output can be chosen after the point is known. `docs/spec/gkr.md` §5.2.
    pub const GKR_OUTPUTS: u64 = 25;

    /// Challenge. One coordinate of a GKR circuit's top-layer point, drawn
    /// after [`GKR_OUTPUTS`].
    pub const GKR_OUTPUT_POINT: u64 = 26;

    /// Challenge. The RLC that batches a layer transition's claims — one per
    /// column of the layer written, then its enforcing gates — into the one
    /// claim its sumcheck proves. Drawn after every claim it batches is
    /// absorbed.
    pub const GKR_BATCH: u64 = 27;

    /// Scalars. The claimed values of the layer a transition reads, at the
    /// point its sumcheck bound, in one message: one per column, or both
    /// children per column for a halving transition.
    pub const GKR_LAYER_CLAIMS: u64 = 28;

    /// Challenge. The point `τ` on the line through a halving transition's
    /// two child claims, drawn after both are absorbed.
    pub const GKR_CHILD: u64 = 29;

    /// Scalars. The statement's RAM window list `[w_1 … w_k]`, the
    /// `ZERO_WINDOWS` family's shard windows ascending, absorbed immediately
    /// after [`SHARD_COUNTS`] and before program identity.
    /// `docs/spec/memory.md` §6.1.
    pub const MEMORY_WINDOWS: u64 = 30;

    /// Scalars. The 64 register and pc boundary scalars
    /// `[t_0 … t_31, t_pc, v_1 … v_31]`, one message, absorbed after every
    /// memory-column commitment and before the memory challenges are drawn.
    /// `docs/spec/memory.md` §4.1 and §6.1.
    pub const MEMORY_BOUNDARY: u64 = 31;

    /// Scalars. The program-identity sponge's `entry_pc`, one element,
    /// absorbed after [`VM_CONFIG`] and before the families' commitments.
    /// `docs/spec/memory.md` §6.2.
    pub const PROGRAM_ENTRY: u64 = 32;

    /// Challenge. The LogUp channels' two shard-local challenges, `g` then
    /// `β`, drawn in that order after every witness and multiplicity
    /// commitment of the shard is absorbed. One tag, one kind; the two roles
    /// are separated by their fixed position in the shard's script, as
    /// [`SUMCHECK_CHALLENGE`]'s are. `docs/spec/lookup.md` §2.
    pub const LOOKUP_CHALLENGE: u64 = 33;

    /// Scalars. The statement's SRS digest, one element, absorbed right after
    /// the protocol suite message. `docs/spec/shard-proof.md` §2 and §3.
    pub const SRS_DIGEST: u64 = 34;

    /// Bytes. The 320-byte `SrsVerifier` encoding, inside the SRS digest's own
    /// sponge, whose raw squeeze is the digest. `docs/spec/shard-proof.md` §3.
    pub const SRS_VERIFIER: u64 = 35;

    /// Scalars. `[family, shard count]`, opening one family's memory-column
    /// group in the global transcript; the group's commitment lists follow it
    /// under [`COMMITMENT`]. `docs/spec/shard-proof.md` §2.
    pub const MEMORY_GROUP: u64 = 36;

    /// Challenge. The global memory challenges `γ_M, α_addr, α_ts, α_val`,
    /// drawn in that order after the boundary scalars. One tag, one kind; the
    /// four roles are separated by position. `docs/spec/shard-proof.md` §2.
    pub const MEMORY_CHALLENGE: u64 = 37;

    /// Challenge. The global state digest, drawn once after the memory
    /// challenges; every shard transcript is seeded with it.
    /// `docs/spec/shard-proof.md` §2.
    pub const GLOBAL_STATE_DIGEST: u64 = 38;

    /// Scalars. `[global state digest, family, shard index]`, the first message
    /// of every shard transcript. `docs/spec/shard-proof.md` §4.
    pub const SHARD_SEED: u64 = 39;

    /// Scalars. `[start, end]`, the shard's timestamp window, immediately after
    /// the seed. `docs/spec/shard-proof.md` §4.
    pub const SHARD_TS_WINDOW: u64 = 40;

    /// Scalars. The packed generic table's three commitments the verifying
    /// key carries, each point four limbs, as one twelve-limb message inside
    /// the SRS digest's own sponge, right after [`SRS_VERIFIER`]. Added at
    /// S17, the first stage whose family reads the generic channel.
    /// `docs/spec/shard-proof.md` §3.
    pub const GENERIC_TABLE: u64 = 41;

    /// Every tag's name, indexed by `tag - 1`. **Documentation, never
    /// semantics**, as `challenge_slot::NAMES` is: the number is the tag, and
    /// nothing reads a name to decide anything. `checker::tape` renders a
    /// transcript's absorb sequence with them, which is what makes a tape
    /// diffable against the frozen order of `docs/spec/shard-proof.md` §2.
    ///
    /// Append here whenever a tag is appended above. This crate keeps its
    /// zero-logic rule: the lookup lives in `checker::tape`.
    pub const NAMES: [&str; 41] = [
        "PROTOCOL_SUITE",
        "PUBLIC_INPUTS",
        "COMMITMENT",
        "SUMCHECK_ROUND",
        "SUMCHECK_CHALLENGE",
        "EVALUATION_CLAIM",
        "PCS_OPENING",
        "WITNESS_DIGEST",
        "SUMCHECK_FINAL_EVALS",
        "MERCURY_INSTANCE",
        "MERCURY_ALPHA",
        "MERCURY_GAMMA",
        "MERCURY_Z",
        "BDFG_BATCH",
        "BDFG_POINT",
        "PAIRING_MERGE",
        "MERCURY_BATCH",
        "ACCUMULATOR_DIGEST",
        "ACCUMULATOR_MERGE",
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
        "SRS_DIGEST",
        "SRS_VERIFIER",
        "MEMORY_GROUP",
        "MEMORY_CHALLENGE",
        "GLOBAL_STATE_DIGEST",
        "SHARD_SEED",
        "SHARD_TS_WINDOW",
        "GENERIC_TABLE",
    ];
}

/// The external challenge slots a GKR circuit's coefficients may name, frozen
/// at S13; **append-only**.
///
/// A `constraints::Coeff::Challenge(slot)` names one of these numbers, and the
/// caller supplies its value in `ExternalChallenges`. The number is the
/// semantics; [`challenge_slot::NAMES`] is documentation for dumps and
/// diagnostics, indexed by slot, exactly as a tag's constant name is.
pub mod challenge_slot {
    /// The S13 toy circuit's one challenge. No production circuit reads it.
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
    /// that shard's own transcript, after every witness and multiplicity
    /// commitment is absorbed. `docs/spec/lookup.md` §2.
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

/// The lookup channels a lookup expression names, frozen at S14 and completed
/// at S15; **append-only**.
///
/// A `LookupExpr`'s `channel` is one of these numbers. A channel is either a
/// **range** channel, whose one expression holds on a row when its canonical
/// integer is below `2^BITS[channel]`, or a **table** channel, whose tuple
/// holds when it is a row of the channel's committed table.
/// [`lookup_channel::NAMES`] is documentation, indexed by channel, as
/// [`challenge_slot::NAMES`] is. `docs/spec/memory.md` §7 and
/// `docs/spec/lookup.md`.
pub mod lookup_channel {
    /// Range. The timestamp gap's two 19-bit chunks: `[0, 2^19)`.
    pub const TIMESTAMP: u32 = 0;

    /// Range. A halfword, `[0, 2^16)`: two of them bound a 32-bit value, under
    /// the range convention of `docs/spec/memory.md` §7.
    pub const RANGE16: u32 = 1;

    /// Table. The committed generic tables, packed into one table under the
    /// gated-key convention of `docs/spec/lookup.md` §4.
    pub const GENERIC: u32 = 2;

    /// Table. A family's decoded instruction table, `crates/program`'s
    /// `lookup_tuple(family)` columns in their frozen order.
    pub const DECODER: u32 = 3;

    /// Table. The byte table `(a, b, a ^ b)`, all 65,536 triples, and the
    /// first table channel whose table is **virtual** rather than committed
    /// (S26d, `docs/spec/lookup.md` §14).
    ///
    /// Its three columns are closed forms of the row index — `a` the low
    /// eight bits, `b` the next eight, `a ^ b` their bitwise XOR, which is
    /// multilinear in the row's bits because `y ^ z = y + z - 2yz` is — so it
    /// costs no commitment, no setup column and no movement of the SRS digest.
    ///
    /// **The tuple is three wide and that is the point.** Membership of
    /// `(x, y, z)` forces each of the three into `[0, 256)` individually, so
    /// every byte a circuit feeds it is bounded by the lookup that uses it and
    /// `AND`, `ANDN` and `OR` are linear forms over the result:
    /// `x & y = (x + y - (x ^ y)) / 2`. A packed key `x + 256*y` would be one
    /// column cheaper and would bound neither operand on its own.
    ///
    /// `constants::family::KECCAK_F` is its one consumer: a Keccak round is
    /// 1,020 obligations on it and no bit anywhere
    /// (`docs/spec/delegation.md` §6).
    pub const XOR8: u32 = 4;

    /// How many channels this table defines.
    pub const COUNT: u32 = 5;

    /// Whether channel `i` is a range channel, indexed by channel. A range
    /// channel's table is the closed form of `docs/spec/lookup.md` §3; a table
    /// channel's is committed, or — since S26d's [`XOR8`] — a closed form of
    /// its own.
    pub const IS_RANGE: [bool; COUNT as usize] = [true, true, false, false, false];

    /// A range channel's bound, as a bit width, indexed by channel; 0 where
    /// [`IS_RANGE`] is false, which is not a bound of `[0, 1)` but the absence
    /// of one.
    ///
    /// This is a **bound**, not a table size: what decides the fewest
    /// variables a circuit declaring a channel may be built at is
    /// `constraints::lookup::table_vars`, which reads this for a range channel
    /// and a virtual table channel's key width for one of those.
    pub const BITS: [u32; COUNT as usize] = [19, 16, 0, 0, 0];

    /// Every channel's display name, indexed by channel.
    pub const NAMES: [&str; COUNT as usize] =
        ["timestamp", "range16", "generic", "decoder", "xor8"];

    /// The widest lookup tuple any channel carries: `beta` powers exist for
    /// positions `0 .. MAX_TUPLE`, and `challenge_slot::LOOKUP_BETA_POWERS`
    /// has one slot per position above 0. The decoder's seven-column tuple is
    /// the widest built (`crates/program`'s `lookup_tuple`).
    pub const MAX_TUPLE: usize = 7;
}

/// The generic channel's packed table, frozen at S15 in `crates/program`'s
/// `lookup_tables` and moved here at S17, when a circuit — which cannot
/// depend on `program` — first builds a key into it. S18 appends
/// `ShiftPowers`. `docs/spec/lookup.md` §9.
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

/// The circuit families, by number. Frozen at S11; **append-only**.
///
/// A family is one arithmetization shape covering a set of program counters.
/// The number is what every later stage cites: canonical ordering is ascending
/// `FamilyId`, the program-identity digest absorbs families in that order, and
/// shard transcripts are seeded with it. Delegation families are appended
/// after [`ZERO_WINDOWS`] and never renumber anything below them.
///
/// Which mnemonic each instruction family claims is `crates/program`'s
/// `row_kind`, and `crates/program/CLAUDE.md` is the table.
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
    /// The keccak-f[1600] **delegation** family (S21, re-shaped at S26d): one
    /// Keccak *round* a row, so a permutation is 24 consecutive invocations,
    /// invoked by the [`ecall::PRECOMPILE_KECCAK_F`] ecall and never decoded.
    /// Claims no pc, owns no cycle, and is in a `VmConfig` only when the
    /// linked binary declares it (`docs/spec/delegation.md` §7).
    pub const KECCAK_F: u32 = 9;
    /// The Poseidon2 **delegation** family (S23): one width-3 permutation a
    /// row, invoked by the [`ecall::PRECOMPILE_POSEIDON2`] ecall. The circuit
    /// is `transcript::poseidon2_permute`, gate for gate
    /// (`docs/spec/delegation.md` §12).
    pub const POSEIDON2: u32 = 10;
    /// The Fr-arithmetic **delegation** family (S23): one `Fr` add, multiply
    /// or inverse a row, invoked by the [`ecall::PRECOMPILE_FR_ARITH`] ecall
    /// (`docs/spec/delegation.md` §13).
    pub const FR_ARITH: u32 = 11;
    /// The **public input** window (S-IO): the verifier-known input of the
    /// statement, at [`guest_memory::PUBLIC_INPUT_ORIGIN`]. Claims no pc,
    /// owns no cycle, and is in **every** `VmConfig` at
    /// [`PUBLIC_WINDOW_HEIGHT`], proving exactly one shard.
    ///
    /// Its init column is what the verifier holds to the statement's `input`;
    /// its teardown column is free, because a guest may overwrite its own
    /// input buffer (`docs/spec/public-values.md` §5).
    pub const PUBLIC_INPUT: u32 = 12;
    /// The **public output** window — the journal — (S-IO), at
    /// [`guest_memory::PUBLIC_OUTPUT_ORIGIN`]. In every `VmConfig` at
    /// [`PUBLIC_WINDOW_HEIGHT`], proving exactly one shard.
    ///
    /// Its init leaf is the **literal 0** of [`ZERO_WINDOWS`]' artifact, which
    /// is what stops a prover supplying the journal at timestamp 0 instead of
    /// storing it; its teardown column is what the verifier holds to the
    /// statement's `output` (`docs/spec/public-values.md` §5).
    pub const PUBLIC_OUTPUT: u32 = 13;
    /// The **advice** windows (S-IO): prover-supplied initial values for the
    /// region at [`guest_memory::ADVICE_ORIGIN`], one shard per window, `k`
    /// of them counted from [`guest_memory::ADVICE_ORIGIN`] upward. In every
    /// `VmConfig` at the window height, with `k >= 0` shards.
    ///
    /// **Nothing binds its init column, by design.** Advice is what the
    /// prover chose; a guest owes a check of it against something public
    /// (`docs/spec/public-values.md` §6).
    pub const ADVICE_WINDOWS: u32 = 14;
    /// The **Ethereum field multiplication** delegation family (S26,
    /// specialized at S26b): one `out = a * b mod m` a row over 32-bit limbs,
    /// invoked by the [`ecall::PRECOMPILE_MOD_MUL`] ecall and never decoded
    /// (`docs/spec/delegation.md` §14).
    ///
    /// The modulus is **one of four**, named by a selector word in the frame
    /// and supplied by the circuit as a literal:
    /// [`mod_mul::SECP256K1_P`], [`mod_mul::SECP256K1_N`],
    /// [`mod_mul::BN254_P`] and [`mod_mul::BN254_R`]. Between them those are
    /// every 256-bit field Ethereum block execution multiplies in, and
    /// fixing them is what lets the circuit state `a < m` and `b < m` — so
    /// the quotient is bounded by the statement rather than by the honest
    /// prover's manners.
    ///
    /// It is the opposite choice from [`FR_ARITH`], whose modulus is the
    /// circuit's own field and whose multiply is therefore one degree-2 gate;
    /// a 256-bit modulus does not fit `Fr` at all, so this one proves the
    /// schoolbook identity `a*b = q*m + out` limb by limb with a signed carry
    /// chain.
    ///
    /// **Why it exists**: on a whole mainnet block, 44.4% of the guest's cycles
    /// are 256-bit modular multiply and square inside `k256`, at ~1,300 cycles
    /// a call (`docs/handoff/S26-cycle.md`).
    pub const MOD_MUL: u32 = 15;

    /// Invoked. **Four SHA-256 rounds a row** since S26e, over a 25-word frame:
    /// the round group, the eight working variables and a sixteen-word schedule
    /// window; a compression is 16 rows glued by the frame's RAM. S26c's row
    /// was a whole compression.
    ///
    /// **Why it exists**: Ethereum's `0x02` precompile, and since S-STATELESS
    /// the stateless guest's SSZ merkleization, which is 8,011 compressions on
    /// a 100 Mgas devnet block. The guest keeps the padding and the block
    /// loop, exactly as `guest_sdk::keccak256` keeps the sponge
    /// (`docs/spec/delegation.md` §11).
    pub const SHA256_COMP: u32 = 16;

    /// Invoked. One third of a complete elliptic-curve point addition a row,
    /// over a 97-word frame that is also the scratch the three invocations
    /// pass their intermediates through.
    ///
    /// **Why it exists**: after S26 routed `k256`'s field multiply through
    /// [`MOD_MUL`], 26% of a measured block's guest cycles were still
    /// secp256k1 — the shim's marshalling, `operand`'s reduction and the
    /// ladder's bookkeeping around 12 delegated multiplies a point operation
    /// (`docs/handoff/S26-cycle.md`). Delegating the point operation removes
    /// all of it. The curve is a frame word, because the Renes-Costello-Batina
    /// formula is the same for secp256k1 and BN254 G1 — both `a = 0`, and `b`
    /// never appears.
    pub const EC_ADD: u32 = 17;

    /// How many families this table defines.
    pub const COUNT: u32 = 18;

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
    /// **It was `2^8` until S-STREAM**, which bought 1,020 journal bytes and
    /// a revm mini journal that overflowed above 73 transactions
    /// (`docs/spec/revm-block.md` §2). 16,380 is what the geometry allows; it
    /// is headroom and not a bound, a journal carrying verbatim return data
    /// being unbounded in any window.
    ///
    /// The price is the verifier's step 10c, two 4,096-point multilinear
    /// evaluations rather than two 256-point ones — 8,190 `Fr` multiplies and
    /// 81,920 live bytes a shard (`2^11` `Fr` of fold scratch plus the 4,096
    /// `u32` words of the window itself), 163,840 across the two. Noise on a
    /// native verifier, and a budget a recursion guest will have to carry.
    pub const PUBLIC_WINDOW_HEIGHT: u32 = 1 << 12;

    /// [`PUBLIC_INPUT`]'s window id at [`PUBLIC_WINDOW_HEIGHT`].
    pub const PUBLIC_INPUT_WINDOW: u32 =
        crate::guest_memory::PUBLIC_INPUT_ORIGIN / (4 * PUBLIC_WINDOW_HEIGHT);
    /// [`PUBLIC_OUTPUT`]'s window id at [`PUBLIC_WINDOW_HEIGHT`].
    pub const PUBLIC_OUTPUT_WINDOW: u32 =
        crate::guest_memory::PUBLIC_OUTPUT_ORIGIN / (4 * PUBLIC_WINDOW_HEIGHT);

    /// Whether a family's rows are **execution cycles**, indexed by
    /// `FamilyId`. Append-only, beside the ids themselves.
    ///
    /// The seven instruction families own cycles; [`INIT_TEARDOWN`] and
    /// [`ZERO_WINDOWS`] own addresses — a RAM window's rows are words, not
    /// cycles (`docs/spec/memory.md` §3). A block's time-window rules apply to
    /// cycle-owning families alone (`docs/spec/block-proof.md` §4): only their
    /// shards partition an execution in time. A **delegation** family appends
    /// here as `false`: its rows are invocations, its shards carry a min/max
    /// invocation window, and no disjointness is asked of them
    /// (`docs/spec/delegation.md` §8). [`KECCAK_F`] is the first.
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
        false, // KECCAK_F
        false, // POSEIDON2
        false, // FR_ARITH
        false, // PUBLIC_INPUT
        false, // PUBLIC_OUTPUT
        false, // ADVICE_WINDOWS
        false, // MOD_MUL
        false, // SHA256_COMP
        false, // EC_ADD
    ];

    /// The trace-height menu, ascending. Even powers of two only, so that a
    /// Mercury opening's `b = sqrt(n)` exists.
    ///
    /// `2^8` is S21's, and it is a **delegation** height: a row too wide to
    /// afford at any ordinary height can still be afforded 256 of them. S21
    /// opened the menu with it because one keccak row was a whole
    /// keccak-f[1600] permutation at ~345,600 inner columns, and a shard's
    /// forward pass is columns times height. S26d made one keccak row one
    /// *round*, and that family sits at `2^18` today, as does `SHA256_COMP`
    /// since S26e made one of its rows four rounds; what keeps `2^8` on the
    /// menu is `POSEIDON2` and `FR_ARITH` (`docs/spec/delegation.md` §9). What closes `2^8` to a family is a
    /// channel whose **table needs more than eight variables**, not carrying a
    /// channel at all: `constraints::lookup::table_vars` is 19 for `TIMESTAMP`
    /// and 16 for `RANGE16` and `XOR8`, so any of those three forces `2^16` or
    /// above, while `GENERIC` and `DECODER` report **0** — their tables are
    /// committed setup rather than closed forms, so they raise the floor by
    /// nothing. `constraints::family_circuit` returns `None` below the widest
    /// table its channels declare, and nothing today rests on the two zeros:
    /// all five families reading `GENERIC` also carry `TIMESTAMP`, whose 19
    /// puts them at `2^20` regardless.
    /// `2^12` is S-STREAM's, and it is the two **public-value** families' and
    /// nothing else's: it is below every channel floor an execution family
    /// reaches, and a window family at `2^12` reaches `0x4000`, short of the
    /// public windows' end, so `verifier_core::window_height` refuses it. What
    /// it does widen is what a key may declare for the three channel-free
    /// delegation families, which is benign and bought nothing.
    pub const HEIGHT_MENU: [u32; 6] = [1 << 8, 1 << 12, 1 << 16, 1 << 18, 1 << 20, 1 << 22];

    /// The default trace height of every family, indexed by `FamilyId`.
    ///
    /// **No execution family may default below `2^20`.** A circuit carrying a
    /// timestamp gap obligation needs `lookup_channel::BITS[TIMESTAMP] = 19`
    /// variables (`docs/spec/lookup.md` §3), and a Mercury opening needs an
    /// even count, so `2^20` is the floor for every family that runs cycles.
    /// `ATOMICS` sat at `2^16` from S11 until S19 raised it with the circuit
    /// that needs it (`docs/handoff/S16-add-sub.md` answer 7).
    ///
    /// A **delegation** family is the other way round: its floor is whatever
    /// its own channels imply — 0 for the two that carry none — and its
    /// ceiling is its own circuit's width. Those widths differ by **orders of
    /// magnitude**, so the six do not share a height and there is no reason
    /// they should: [`FR_ARITH`] is 142 inner columns a row where [`KECCAK_F`]
    /// is 5,490 at `2^18`. **That ceiling is a judgement and not a
    /// wall**, and [`KECCAK_F`]'s `2^18` is what shows it: ~60 GB a shard is
    /// payable there because a keccak-heavy block has tens of thousands of
    /// invocations to amortise it over. [`SHA256_COMP`] took the same height
    /// for the same reason at S26e — S26c's whole-compression row was 16,688
    /// inner columns and pinned it to `2^8`, and four rounds a row is 2,802 —
    /// once the stateless guest's SSZ hashing made it 32 shards and two thirds
    /// of a real block's proof. Below that ceiling the height is a **proof-size**
    /// decision — a `2^8` shard's proof does not shrink with its height, so a
    /// family's height is what decides how many shards a block's invocations
    /// take, and `MOD_MUL` at `2^8` cost a measured block 1,048 shards against
    /// 5 at `2^16` (`docs/spec/delegation.md` §9 and §9.1).
    ///
    /// [`KECCAK_F`] is the case that shows the trade is about **width**, not
    /// rows. At S21 one row was a whole permutation — 354,762 inner columns,
    /// `2^16` of them 744 GB — so it sat at `2^8` and 256 permutations a shard,
    /// which made five keccak shards 97% of a measured mini-block's proof
    /// bytes. S26d made one row one *round*: 24 rows a permutation, ~5,490
    /// inner columns each, and `2^18` is ~60 GB — 10,922 permutations a shard
    /// and, per permutation, half the columns of the old shape. `2^16` is only
    /// the **floor** its two channels imply; `2^18` is the choice above it,
    /// because a shard's proof barely grows with its height — 381,100 bytes
    /// against 373,276 — so the fatter shard is the cheaper one for a
    /// keccak-heavy block (`docs/spec/delegation.md` §6.0, §9.2).
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
        1 << 18, // KECCAK_F: CHOSEN above its floor of 16 (RANGE16 and XOR8)
        1 << 8,  // POSEIDON2
        1 << 8,  // FR_ARITH
        1 << 12, // PUBLIC_INPUT, and it is the only admissible one
        1 << 12, // PUBLIC_OUTPUT, likewise
        1 << 22, // ADVICE_WINDOWS, at the window height
        1 << 16, // MOD_MUL, and NOT 2^8 — see the paragraph above
        1 << 18, // SHA256_COMP: CHOSEN above its floor of 16 (RANGE16 and XOR8)
        1 << 16, // EC_ADD: forced, its RANGE16 table needing 16 variables
    ];

    /// The default `bytecode_size_words`: `2^20` words, a 4 MiB ceiling on the
    /// span from `RAM_ORIGIN` to the last file-backed byte of the image.
    pub const DEFAULT_BYTECODE_SIZE_WORDS: u32 = 1 << 20;

    /// The version of the decoded-table construction. Absorbed first into the
    /// program-identity sponge. Changing it re-registers every program.
    pub const CODE_VERSION: u32 = 0;
}

/// The bit positions of `family_extra_mask`, per family. Frozen at S11;
/// **append-only**.
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

/// The guest memory map, frozen at S10 and re-frozen after S12 on the
/// repository owner's instruction. These are the frozen values.
///
/// The one region a guest has. `crates/guest-sdk/link.ld` states the same two
/// numbers for the linker, `docs/spec/ecall-abi.md` section 7 states them for a
/// reader, and `crates/constants/tests/ecall_abi.rs` checks all three against
/// each other — a memory map written down three times is a memory map that can
/// disagree with itself.
///
/// `crates/loader` refuses a `PT_LOAD` segment that does not lie inside this
/// window. Nothing outside it is addressable, so a program that wants to be
/// there is not a program this VM can run — and enforcing it also bounds what
/// a hostile ELF can make the loader allocate.
pub mod guest_memory {
    /// First addressable byte, and where `_start` is placed.
    pub const RAM_ORIGIN: u32 = 0x0001_0000;

    /// Length of the region. `RAM_ORIGIN + RAM_LENGTH` is the initial `sp`,
    /// and lands on `0x8000_0000` — a window of just under 2 GiB.
    pub const RAM_LENGTH: u32 = 0x7FFF_0000;

    /// The top of RAM the stack keeps for itself, added at S12. guest-sdk's
    /// allocator never hands out a block reaching into the last
    /// `STACK_RESERVE` bytes below `RAM_ORIGIN + RAM_LENGTH`, nor one above
    /// the live `sp`. 8 MiB: a native main thread's default stack on Linux and
    /// macOS, so a program whose recursion fits on the host fits here. Not
    /// part of the linker's map — `link.ld` has no symbol for it — but a
    /// number the SDK, its documents and its probe guest must agree on.
    pub const STACK_RESERVE: u32 = 0x0080_0000;

    /// First byte of the **public input** window: the verifier-known input a
    /// statement is about (`docs/spec/public-values.md` §2).
    ///
    /// `[0, RAM_ORIGIN)` is already a hole. `INIT_TEARDOWN` masks RAM window
    /// 0's rows below `2^14` with `V[ram_live]` and `ZERO_WINDOWS` never
    /// claims window 0, so no RAM window family initializes an address there
    /// (`docs/spec/memory.md` §3.3). Two windows of that hole are therefore
    /// free to claim without moving a single existing row, and `[0, 0x8000)`
    /// stays a hole: a null dereference is still a read of a tuple nothing
    /// wrote, and cannot balance. Since S-STREAM the two windows take the
    /// **whole** of the hole above `0x8000` — `2^12` each, ending flush
    /// against `RAM_ORIGIN` — which is what makes that height the ceiling.
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
    /// 3 and ends flush against [`RAM_ORIGIN`]: the hole holds exactly two
    /// public windows and no more. It was `0x8400` until S-STREAM, when the
    /// height left `2^8`.
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

    /// First byte of the **advice** region: prover-supplied, uncommitted
    /// witness data, read with ordinary loads
    /// (`docs/spec/public-values.md` §6).
    ///
    /// It sits above RAM rather than inside it, so it competes with no heap
    /// and no stack, and `[RAM_ORIGIN, ADVICE_ORIGIN)` keeps exactly the
    /// meaning it had. The address-space tag is [`address_space::RAM`] here
    /// too: what makes an advice word advice is that its window family's init
    /// column is committed and bound to nothing, not a tag a load would have
    /// to name.
    pub const ADVICE_ORIGIN: u32 = 0x8000_0000;

    /// Words the advice region spans: `[ADVICE_ORIGIN, 2^32)`, 2 GiB.
    pub const ADVICE_WORDS: u32 = 1 << 29;
}

/// The guest ecall ABI: the numbers and the range boundaries, in one place
/// forever.
///
/// **Append-only.** Once a program's identity is published its ABI is frozen.
/// Redefining a number does not fail loudly — it quietly makes an old program
/// compute something else — so numbers here are assigned once and never
/// reused, exactly like `transcript_tags`. *Retiring* a number obeys the same
/// rule from the other side: it is struck out and never reassigned. `READ`
/// (63) and `WRITE` (64) were retired when the POSIX compatibility layer was
/// deleted, and **63 and 64 are burned** — append-only forbids giving them a
/// second meaning, not deleting a call nothing may issue.
///
/// An ecall carries its number in `a7`, its arguments in `a0`-`a5` and its
/// result in `a0`, with errors as a negated errno. **An Apogee guest is an
/// Apogee-SDK program, not a Linux one**: it has no file descriptors, no
/// streams and no I/O syscall at all. Its public input, its advice and its
/// journal are *memory the proof system binds* — ordinary loads and stores
/// against three fixed regions (`docs/spec/public-values.md`) — so the only
/// ecalls a guest issues are [`EXIT`] and the delegation numbers below, which
/// are exactly the provable ones. `docs/spec/ecall-abi.md` is the normative
/// table.
pub mod ecall {
    /// Terminate. `a0` is the exit status; a nonzero status is a failed
    /// execution, which is still an execution and is reported rather than
    /// refused.
    ///
    /// The only non-delegation ecall a guest may issue. Its number is 93
    /// because that is what it has always been here, and append-only keeps it
    /// there; nothing downstream reads any meaning into the value.
    pub const EXIT: u32 = 93;

    /// First number of the zkVM-specific host-call range, `0x0400..=0x04FF`.
    ///
    /// **Reserved and empty, and it stays that way.** A call here would be
    /// nondeterministic prover advice, and advice does not need a syscall: it
    /// is a memory region the prover fills and the guest authenticates
    /// (`docs/spec/public-values.md` §6). Kept disjoint from
    /// [`PRECOMPILE_FIRST`] so a reviewer can tell prover advice from a proven
    /// function at a glance.
    pub const ZKVM_IO_FIRST: u32 = 0x0400;

    /// Last number of the zkVM-specific host-call range.
    pub const ZKVM_IO_LAST: u32 = 0x04FF;

    /// First number of the precompile range, `0x0500..=0x05FF`.
    ///
    /// A precompile is a **deterministic function of guest memory**, dispatched
    /// by ecall with pointer arguments in `a0`-`a5` because its operands do not
    /// fit in registers. Every precompile shim lands in this range.
    pub const PRECOMPILE_FIRST: u32 = 0x0500;

    /// Last number of the precompile range.
    pub const PRECOMPILE_LAST: u32 = 0x05FF;

    /// Poseidon2 permutation over a `[Fr; 3]` state, `a0` = the 96-byte frame
    /// base pointer, read and written in place.
    ///
    /// Assigned at S10 and given its circuit at S23: a **delegation** call,
    /// `docs/spec/delegation.md` is its ABI and `constants::family::POSEIDON2`
    /// the family that proves it. The three lanes cross the frame as canonical
    /// little-endian `Fr`, 8 words each, lane `i` at words `8i..8i + 8`.
    pub const PRECOMPILE_POSEIDON2: u32 = 0x0500;

    /// **Retired and burned at S26d.** `0x0501` was S21's keccak-f[1600] over
    /// a 200-byte frame holding the state and nothing else: **one call, one
    /// whole permutation**. S26d made one round one invocation, which needs a
    /// 204-byte frame whose word 0 is the round — a different call with
    /// different semantics, and append-only forbids giving a number a second
    /// meaning. An old binary issuing `0x0501` under the new executor would
    /// have its first state word read as a round selector and get one round of
    /// a permuted state back, with nothing failing loudly.
    ///
    /// It is a constant rather than a comment for the reason
    /// [`RETIRED_MOD_MUL_WITNESSED_MODULUS`] is:
    /// `crates/constants/tests/ecall_abi.rs` reads it, and a number in the
    /// source is a number a test can hold to being unanswered.
    pub const RETIRED_KECCAK_F_WHOLE_PERMUTATION: u32 = 0x0501;

    /// One `Fr` add, multiply or inverse over a 25-word frame, `a0` = the
    /// frame base pointer, read and written in place. A **delegation** call
    /// (S23); `constants::family::FR_ARITH` is the family that proves it and
    /// `docs/spec/delegation.md` §13 the frame table.
    ///
    /// The operands cross the frame in `field::Fr`'s **in-memory**
    /// representation — the four Montgomery limbs, little-endian, which is a
    /// canonical little-endian encoding of a field element and is checked to
    /// be one in-circuit. The three operations are exactly what `Fr`'s `Add`,
    /// `Mul` and `inverse` compute on those representatives, so the delegated
    /// path and the software fallback are the same function by construction.
    pub const PRECOMPILE_FR_ARITH: u32 = 0x0502;

    /// **Retired and burned at S26b.** `0x0503` was S26's modular
    /// multiplication over a 32-word frame carrying a **witnessed** 256-bit
    /// modulus. S26b specialized that family to four fixed moduli named by a
    /// selector, which is a different 25-word frame with different semantics,
    /// and append-only forbids giving a number a second meaning — an old
    /// binary calling `0x0503` with a 32-word frame under the new executor
    /// would read the modulus as a selector and compute something else, with
    /// nothing failing loudly. So the specialized call took the next free
    /// number and this one may never be issued or reassigned.
    ///
    /// It is a constant rather than a comment for the reason [`EXIT`]'s number
    /// is: `crates/constants/tests/ecall_abi.rs` reads it, and a number in the
    /// source is a number a test can hold to being unanswered.
    pub const RETIRED_MOD_MUL_WITNESSED_MODULUS: u32 = 0x0503;

    /// One **Ethereum field multiplication** over a 25-word frame, `a0` = the
    /// frame base pointer, read and written in place. A **delegation** call
    /// (S26, specialized at S26b); `constants::family::MOD_MUL` is the family
    /// that proves it and `docs/spec/delegation.md` §14 the frame table.
    ///
    /// Frame word 0 is the modulus selector, one of
    /// [`super::mod_mul::CODES`]; the two operands and the result follow it as
    /// eight 32-bit little-endian limbs each. The call is
    /// `out = a * b mod m` for the **selected** modulus, with `a` and `b`
    /// required to be below it and the result below it too. The invocation
    /// writes the result's eight words and nothing else.
    ///
    /// **It is not `MULMOD`.** An arbitrary modulus has no representation
    /// here and the EVM's opcode runs through the ordinary RV32 path.
    pub const PRECOMPILE_MOD_MUL: u32 = 0x0504;

    /// **Retired and burned at S26e.** `0x0505` was S26c's SHA-256 over a
    /// 96-byte frame holding the chaining state and one block: **one call, one
    /// whole compression**. S26e made one call four rounds, which needs a
    /// 100-byte frame whose word 0 is the round group — a different call with
    /// different semantics, and an old binary issuing `0x0505` under the new
    /// executor would have its first state word read as a group and get four
    /// rounds of a shuffled state back, with nothing failing loudly. The
    /// re-shaped call took [`PRECOMPILE_SHA256_COMP`] = `0x0508`.
    pub const RETIRED_SHA256_COMP_WHOLE_COMPRESSION: u32 = 0x0505;

    /// **Four rounds** of SHA-256's compression over a 25-word frame, `a0` =
    /// the frame base pointer, read and written in place. A **delegation**
    /// call (S26c, re-shaped at S26e); `constants::family::SHA256_COMP` is the
    /// family that proves it and `docs/spec/delegation.md` §15 the frame table.
    ///
    /// Frame word 0 is the round group `r` in `0..16`, words 1..9 the working
    /// variables and words 9..25 the schedule window `W_{4r}..W_{4r+15}`. The
    /// call runs rounds `4r..4r + 4`, writes the working variables after them,
    /// and writes the window back shifted by four with the four schedule words
    /// it derived last. **A whole compression is 16 of these calls** on one
    /// frame, as a permutation is 24 `KECCAK_F` calls.
    ///
    /// **It is not the hash.** Padding, the length encoding, the block loop
    /// and the final `H + V` stay in guest code, exactly as the sponge does
    /// for keccak.
    pub const PRECOMPILE_SHA256_COMP: u32 = 0x0508;

    /// One **third of an elliptic-curve point addition** over a 97-word frame,
    /// `a0` = the frame base pointer, read and written in place. A
    /// **delegation** call (S26c); `constants::family::EC_ADD` is the family
    /// that proves it and `docs/spec/delegation.md` §16 the frame table.
    ///
    /// Frame word 0 selects the curve **and** the group of three reductions
    /// this invocation performs, one of [`super::ec_add::CODES`]; the two
    /// input points and the six intermediates follow it as eight 32-bit
    /// little-endian limbs each. Three invocations in ascending group order
    /// complete one addition, and the intermediates each leaves in the frame
    /// are what the next picks up.
    ///
    /// **It is not a scalar multiplication.** The ladder stays in guest code.
    pub const PRECOMPILE_EC_ADD: u32 = 0x0506;

    /// **One round** of keccak-f[1600] over a 51-word frame whose word 0 is
    /// the round and whose remaining 50 words are the 1,600-bit state, `a0` =
    /// the frame base pointer, read and written in place. A **delegation** call (S21, re-shaped at S26d);
    /// `constants::family::KECCAK_F` is the family that proves it and
    /// `docs/spec/delegation.md` §6 the frame table.
    ///
    /// **A whole permutation is 24 of these calls**, exactly as a complete
    /// point addition is three `EC_ADD` calls: the frame is ordinary RAM, so
    /// the global memory multiset is what proves round `r`'s output is round
    /// `r + 1`'s input, and the guest's own proven loop is what supplies the
    /// 24 round numbers. S21's whole-permutation call was
    /// [`RETIRED_KECCAK_F_WHOLE_PERMUTATION`].
    pub const PRECOMPILE_KECCAK_F: u32 = 0x0507;

    /// Linux `ENOSYS`. An unimplemented number returns `-ENOSYS` in `a0`.
    ///
    /// It survives the deletion of the POSIX layer because it is not part of
    /// it: it is the delegation ABI's "this executor has no circuit for that"
    /// answer (`docs/spec/delegation.md` §2), which every shim checks for so a
    /// caller can run its own software path. This VM implements all four
    /// delegations, so its executor never answers `-ENOSYS` to one; what it
    /// still answers `-ENOSYS` to is a number nobody has assigned.
    pub const ENOSYS: u32 = 38;
}

/// The memory argument's address spaces, frozen at S12.
///
/// A memory query names one of these, and the tag is the `AS` term of the
/// compressed tuple `gamma_M + AS + alpha_addr*ADDR + ...`. The tags are
/// nonzero on purpose: `(REG, x0, ts 0, value 0)` is a real initial tuple, and
/// with `REG = 0` it would be the all-zero tuple — the same reason the decoded
/// tables pad with `MINUS_ONE` rather than 0. Append-only.
pub mod address_space {
    /// The 32 registers. A query's address is the register index, `0..32`.
    pub const REG: u8 = 1;
    /// Guest RAM, word-granular. A query's address is the byte address of the
    /// 4-aligned word, so always a multiple of 4.
    pub const RAM: u8 = 2;
    /// The program counter: one address, `0`. Every cycle reads `pc` and
    /// writes `next_pc` here.
    pub const PC: u8 = 3;
    /// The **delegation** anchor space of `family::KECCAK_F` (S21).
    ///
    /// Not memory: no guest instruction reaches it, no RAM window initializes
    /// it, and no chain runs through it. Its balance is a bijection — one
    /// delegation request's read against one invocation's answer tuple,
    /// stamped 0 (`docs/spec/delegation.md` §5). A tuple at timestamp 0 is
    /// exactly what makes that pairing 1:1; in [`RAM`] the same tuple would
    /// collide with a window family's init write, and a request with no
    /// invocation would balance.
    ///
    /// **Each delegation family takes the next tag**, append-only. The tag
    /// *is* the delegation type, which is why a keccak request cannot be
    /// answered by another type's invocation at the same frame base; the
    /// anchor's address is the frame base and carries no type of its own.
    ///
    /// With more than one type the requesting row can no longer name its tag
    /// with a literal, because one `deleg` frame query serves every type: the
    /// tag rides the frame's `deleg_space` column instead, which the row's
    /// type selectors pin (`docs/spec/delegation.md` §5.1).
    pub const DELEGATION_KECCAK_F: u8 = 4;

    /// The delegation anchor space of `family::POSEIDON2` (S23). As
    /// [`DELEGATION_KECCAK_F`] in every respect but the type it names.
    pub const DELEGATION_POSEIDON2: u8 = 5;

    /// The delegation anchor space of `family::FR_ARITH` (S23).
    pub const DELEGATION_FR_ARITH: u8 = 6;

    /// The delegation anchor space of `family::MOD_MUL` (S26).
    pub const DELEGATION_MOD_MUL: u8 = 7;

    /// The delegation anchor space of `family::SHA256_COMP` (S26c).
    pub const DELEGATION_SHA256_COMP: u8 = 8;

    /// The delegation anchor space of `family::EC_ADD` (S26c).
    pub const DELEGATION_EC_ADD: u8 = 9;

    /// Every delegation tag, ascending, **append-only**: the one place the set
    /// is written down, so a reader of a memory event can tell a delegation
    /// anchor from RAM, a register or the pc without knowing which family it
    /// belongs to.
    ///
    /// `constraints::memory::frame_query_takes` and `trace::AddressSpace` both
    /// read it; the `deleg` frame query takes an event in **any** of these
    /// spaces, and nothing else does.
    pub const DELEGATION: [u8; 6] = [
        DELEGATION_KECCAK_F,
        DELEGATION_POSEIDON2,
        DELEGATION_FR_ARITH,
        DELEGATION_MOD_MUL,
        DELEGATION_SHA256_COMP,
        DELEGATION_EC_ADD,
    ];
}

/// The memory argument's clock, frozen at S12 from the master's memory
/// invariant, and the memory argument's own numbers, frozen at S14.
///
/// Cycle `c` occupies timestamps `TS_STEP * c + delta` for the four in-cycle
/// slots `delta` in `0..TS_STEP`. Timestamp 0 is the initial write of every
/// address, so the first executed cycle is **cycle 1**: a cycle-0 pc query
/// would write at timestamp 0 and could not strictly follow the initial write
/// it reads. Every timestamp is below `2^TS_BITS`.
///
/// `docs/spec/memory.md` is normative for everything S14 added here.
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

/// The **delegation** ABI's numbers, frozen at S21. `docs/spec/delegation.md`
/// is the ABI itself; this module is the one place its numbers live.
///
/// A delegation family is *invoked*, never decoded: it sets no family bit, it
/// runs its own trace beside the CPU families, and a requesting cycle hands it
/// a frame base pointer in `a0`. Every number here is append-only, for the
/// same reason [`ecall`]'s are — a published identity's ABI is frozen, and
/// redefining a number quietly makes an old program compute something else.
pub mod delegation {
    /// The in-cycle slot (`delta`) of every frame access an invocation makes:
    /// **0**, the requesting cycle's first.
    ///
    /// Zero for two reasons. An invocation is not part of the requesting
    /// instruction's frame at all — it happens at the top of the cycle, before
    /// the row's own register reads — and `(RAM, 0)` is a pair **no query of
    /// `constraints::memory`'s table has**, which is what lets the frame
    /// builder pass over an invocation's events instead of trying to file them
    /// in the requesting family's frame. The narrow-frame panic beside that
    /// rule is unchanged: a pair the table *does* have and no free slot takes
    /// is still loud.
    pub const FRAME_DELTA: u64 = 0;

    /// The in-cycle slot of a request's mirror query and of the invocation's
    /// answer tuple: **3**, which is `constraints::memory::FRAME_DELTA`'s
    /// entry for the `deleg` query and must stay equal to it.
    ///
    /// The two sides of the anchor meet at this timestamp, which is what binds
    /// an invocation to its requesting cycle (`docs/spec/delegation.md` §5.3).
    pub const ANCHOR_DELTA: u64 = 3;

    /// The eight bytes that open a delegation declaration record in a guest
    /// image. `docs/spec/delegation.md` §7.
    ///
    /// The record is [`MARKER_BYTES`] long: this magic, then the declared
    /// ecall number as a little-endian `u32`. The guest SDK emits one per
    /// delegation shim, in an allocated `.rodata` section, so the linker keeps
    /// it exactly when the shim is linked and `crates/loader` carries it into
    /// the image like any other file-backed byte — where program identity
    /// already binds it.
    ///
    /// **Scanned at every byte offset, not at an alignment.** A `static`'s
    /// address is the linker's, and a record that happened to land off a word
    /// boundary would be a declaration silently lost — a build that proves
    /// nothing rather than one that fails.
    pub const MARKER_MAGIC: [u8; 8] = *b"APOGDEL1";

    /// A declaration record's length: [`MARKER_MAGIC`] then a `u32`.
    pub const MARKER_BYTES: usize = 12;

    /// **The delegation registry**: every delegation type, ascending by family
    /// id, as `(family, ecall number, address-space tag, frame words)`.
    /// Append-only, and the one place the four are tied together —
    /// `program::DELEGATIONS` is this table, `constraints::add_sub` builds one
    /// selector and one number gate per row of it, `constraints`' circuits
    /// take their tag from it, and `emulator` dispatches on it.
    ///
    /// `docs/spec/delegation.md` §3 is the same table in prose, and
    /// `crates/constants/tests/ecall_abi.rs` holds the two equal.
    pub const TYPES: [(u32, u32, u8, usize); 6] = [
        (
            super::family::KECCAK_F,
            super::ecall::PRECOMPILE_KECCAK_F,
            super::address_space::DELEGATION_KECCAK_F,
            super::keccak::FRAME_WORDS,
        ),
        (
            super::family::POSEIDON2,
            super::ecall::PRECOMPILE_POSEIDON2,
            super::address_space::DELEGATION_POSEIDON2,
            super::poseidon2::FRAME_WORDS,
        ),
        (
            super::family::FR_ARITH,
            super::ecall::PRECOMPILE_FR_ARITH,
            super::address_space::DELEGATION_FR_ARITH,
            super::fr_arith::FRAME_WORDS,
        ),
        (
            super::family::MOD_MUL,
            super::ecall::PRECOMPILE_MOD_MUL,
            super::address_space::DELEGATION_MOD_MUL,
            super::mod_mul::FRAME_WORDS,
        ),
        (
            super::family::SHA256_COMP,
            super::ecall::PRECOMPILE_SHA256_COMP,
            super::address_space::DELEGATION_SHA256_COMP,
            super::sha256::FRAME_WORDS,
        ),
        (
            super::family::EC_ADD,
            super::ecall::PRECOMPILE_EC_ADD,
            super::address_space::DELEGATION_EC_ADD,
            super::ec_add::FRAME_WORDS,
        ),
    ];
}

/// keccak-f[1600] and keccak256, frozen at S21.
///
/// The permutation's shape and its two constant tables. Four consumers read
/// them and none of them defines its own: `constraints::keccak` builds the
/// circuit, `emulator` executes the delegation ecall, `guest-sdk` runs the
/// software fallback, and the test oracles check all three against
/// `tiny-keccak`.
pub mod keccak {
    /// Lanes in the state: 5 by 5.
    pub const LANES: usize = 25;
    /// Bits in a lane.
    pub const LANE_BITS: usize = 64;
    /// Bits in the state: `LANES * LANE_BITS`.
    pub const STATE_BITS: usize = LANES * LANE_BITS;
    /// Bytes in the state: 200.
    pub const STATE_BYTES: usize = STATE_BITS / 8;
    /// 32-bit words the state occupies in the frame: 50. Lane `i = 5y + x`
    /// occupies state words `2i` and `2i + 1`, low half first
    /// (`docs/spec/delegation.md` §4).
    pub const STATE_WORDS: usize = STATE_BYTES / 4;
    /// Rounds of the permutation.
    pub const ROUNDS: usize = 24;

    /// The frame's word 0: the round this invocation performs, in `0..ROUNDS`.
    ///
    /// **A whole permutation is 24 invocations, not one** (S26d). One round is
    /// one delegation row, the 24 rows of a permutation are glued by the frame
    /// being ordinary RAM, and the guest's own proven loop supplies the round.
    /// `docs/spec/delegation.md` §6.
    pub const ROUND_WORD: usize = 0;

    /// The frame's first state word, one past [`ROUND_WORD`].
    pub const STATE_WORD: usize = ROUND_WORD + 1;

    /// 32-bit words in the frame: the round selector and the state.
    pub const FRAME_WORDS: usize = STATE_WORD + STATE_WORDS;

    /// The frame in bytes, which is what a shim hands over.
    pub const FRAME_BYTES: usize = 4 * FRAME_WORDS;

    /// The byte positions of a lane that iota can change.
    ///
    /// Keccak's round constants set only the bits `2^j - 1` for `j` in `0..7`
    /// — bits 0, 1, 3, 7, 15, 31 and 63 — so a round constant's little-endian
    /// bytes are zero everywhere but here, and iota is four byte XORs rather
    /// than eight. [`IOTA_BYTES_ARE_THE_ONLY_ONES`] holds
    /// [`ROUND_CONSTANTS`] to it.
    ///
    /// **It is not a micro-optimisation.** The `KECCAK_F` circuit's `XOR8`
    /// channel carries 1,020 obligations a row with these four and 1,024 with
    /// eight, and a LogUp fraction tree is padded to a power of two: the four
    /// extra obligations would double the tree and cost 4,096 more inner
    /// columns — another **34.4 GB** a shard at `2^18`, on the family that
    /// already sets a block's peak (`docs/spec/delegation.md` §6.5).
    pub const IOTA_BYTES: [usize; 4] = [0, 1, 3, 7];

    /// Every byte position [`IOTA_BYTES`] omits is zero in every round
    /// constant, checked at compile time because the circuit's shape rests on
    /// it and a wrong answer here is a wrong permutation.
    pub const IOTA_BYTES_ARE_THE_ONLY_ONES: () = {
        let mut mask = 0u64;
        let mut i = 0;
        while i < IOTA_BYTES.len() {
            mask |= 0xffu64 << (8 * IOTA_BYTES[i]);
            i += 1;
        }
        let mut r = 0;
        while r < ROUNDS {
            assert!(
                ROUND_CONSTANTS[r] & !mask == 0,
                "a round constant sets a bit outside IOTA_BYTES"
            );
            r += 1;
        }
    };

    /// keccak256's rate, in bytes: `200 - 2 * 32`.
    pub const RATE_BYTES: usize = 136;
    /// keccak256's digest, in bytes.
    pub const DIGEST_BYTES: usize = 32;
    /// keccak256's padding: `pad10*1` in the **original** Keccak domain, which
    /// is Ethereum's. SHA-3's `0x06` is a different function and is not this.
    pub const PAD_FIRST: u8 = 0x01;
    /// The high bit `pad10*1` sets in the block's last byte.
    pub const PAD_LAST: u8 = 0x80;

    /// The rho rotation offsets, `ROTATIONS[y][x]` for lane `A[x][y]`, a
    /// rotate-**left** on the 64-bit lane. Re-derived from `r = 0`, `(x, y) =
    /// (1, 0)` and `t*(t+1)/2 mod 64` by `crates/constants/tests/keccak.rs`
    /// rather than trusted.
    pub const ROTATIONS: [[u32; 5]; 5] = [
        [0, 1, 62, 28, 27],
        [36, 44, 6, 55, 20],
        [3, 10, 43, 25, 39],
        [41, 45, 15, 21, 8],
        [18, 2, 61, 56, 14],
    ];

    /// The iota round constants, one per round. Re-derived from the degree-8
    /// LFSR of the Keccak reference by `crates/constants/tests/keccak.rs`.
    pub const ROUND_CONSTANTS: [u64; ROUNDS] = [
        0x0000_0000_0000_0001,
        0x0000_0000_0000_8082,
        0x8000_0000_0000_808a,
        0x8000_0000_8000_8000,
        0x0000_0000_0000_808b,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8009,
        0x0000_0000_0000_008a,
        0x0000_0000_0000_0088,
        0x0000_0000_8000_8009,
        0x0000_0000_8000_000a,
        0x0000_0000_8000_808b,
        0x8000_0000_0000_008b,
        0x8000_0000_0000_8089,
        0x8000_0000_0000_8003,
        0x8000_0000_0000_8002,
        0x8000_0000_0000_0080,
        0x0000_0000_0000_800a,
        0x8000_0000_8000_000a,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8080,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8008,
    ];
}

/// The **Poseidon2 delegation** family's shape, frozen at S23.
///
/// The permutation itself is `transcript::poseidon2_permute` and its round
/// constants are [`POSEIDON2_RC3_INITIAL`], [`POSEIDON2_RC3_INTERNAL`] and
/// [`POSEIDON2_RC3_TERMINAL`] — there is no second copy of either, here or in
/// the circuit. This module holds only the numbers the *frame* needs.
pub mod poseidon2 {
    /// The permutation's width, `t`: three `Fr` lanes.
    pub const WIDTH: usize = 3;

    /// Words per `Fr` on the wire: 32 bytes, little-endian.
    pub const WORDS_PER_LANE: usize = 8;

    /// The frame: three lanes of eight words, read and written in place. Lane
    /// `i` occupies words `WORDS_PER_LANE * i .. WORDS_PER_LANE * (i + 1)`.
    pub const FRAME_WORDS: usize = WIDTH * WORDS_PER_LANE;

    /// The frame in bytes, which is what a shim hands over.
    pub const FRAME_BYTES: usize = 4 * FRAME_WORDS;

    /// Full rounds, four before the partial rounds and four after.
    pub const ROUNDS_FULL: usize = 8;

    /// Partial rounds, S-boxing lane 0 alone.
    pub const ROUNDS_PARTIAL: usize = 56;

    /// Every round, in order: the circuit unrolls one layer group apiece.
    pub const ROUNDS: usize = ROUNDS_FULL + ROUNDS_PARTIAL;

    /// S-boxes in one permutation: three a full round, one a partial round.
    pub const SBOXES: usize = 3 * ROUNDS_FULL + ROUNDS_PARTIAL;
}

/// The **Fr-arithmetic delegation** family's shape, frozen at S23.
///
/// One invocation is one operation, and one operation is one trace row: the
/// contraction the recursion guest is sized against is `ops/row = 1`
/// (`docs/spec/delegation.md` §13).
///
/// The three operands cross the frame in `field::Fr`'s **in-memory**
/// representation — the four Montgomery limbs written little-endian, which is
/// a canonical little-endian encoding of a field element and is checked to be
/// one in-circuit. That choice is what makes the delegation worth making: a
/// mathematically-canonical frame would cost a Montgomery conversion per
/// operand, about twice the software multiply the delegation replaces.
pub mod fr_arith {
    /// Words per `Fr` on the wire: 32 bytes, little-endian.
    pub const WORDS_PER_VALUE: usize = 8;

    /// The operation code's word, the frame's first.
    pub const OPCODE_WORD: usize = 0;

    /// The first word of operand `a`.
    pub const A_WORD: usize = 1;

    /// The first word of operand `b`.
    pub const B_WORD: usize = A_WORD + WORDS_PER_VALUE;

    /// The first word of the result. The only words the invocation writes.
    pub const OUT_WORD: usize = B_WORD + WORDS_PER_VALUE;

    /// The frame: the opcode word then three values of eight words.
    pub const FRAME_WORDS: usize = OUT_WORD + WORDS_PER_VALUE;

    /// The frame in bytes, which is what a shim hands over.
    pub const FRAME_BYTES: usize = 4 * FRAME_WORDS;

    /// `out = a + b`, what `Fr`'s `Add` computes on the representatives.
    pub const OP_ADD: u32 = 1;

    /// `out = a * b`, what `Fr`'s `Mul` computes on the representatives —
    /// which, the representatives being Montgomery, is `a·b·R^-1` over `Fr`.
    pub const OP_MUL: u32 = 2;

    /// `out = a.inverse()`, what `Fr`'s `inverse` computes on the
    /// representatives — `R^2·a^-1` over `Fr` — and **0 at `a = 0`**, which is
    /// this delegation's convention rather than `Fr`'s `None`. The backend
    /// answers zero itself and never makes the call.
    pub const OP_INV: u32 = 3;

    /// The operation codes, ascending. Every live row carries exactly one.
    pub const OPS: [u32; 3] = [OP_ADD, OP_MUL, OP_INV];
}

/// The Ethereum field-multiplication delegation's frame, its four moduli and
/// its bounds. Frozen at S26, **specialized at S26b**.
/// `docs/spec/delegation.md` §14.
///
/// **One operation, and the modulus is a selector.** The family computes
/// `out = a * b mod m` and nothing else, over one of **four fixed moduli** a
/// frame word names: the two secp256k1 fields and the two BN254 fields, which
/// between them are every 256-bit field Ethereum block execution multiplies
/// in. S26 carried the modulus in the frame as a witnessed 256-bit operand;
/// S26b removed that, because a runtime modulus bought generality nothing
/// asked for — no caller ever passed one this table does not hold — and cost
/// eight frame words, 256 witness bits and the ability to state `a < m` at
/// all. `docs/handoff/S26b-eth-field-mul.md` is the account.
///
/// **This is not `MULMOD`.** The EVM's opcode takes an arbitrary modulus and
/// runs through the ordinary RV32 path; nothing here serves it.
/// SHA-256's compression function, frozen at S26c and re-shaped at S26e.
///
/// The frame's shape and the algorithm's two constant tables. Three consumers
/// read them and none restates them: `constraints::sha256` builds the circuit,
/// `emulator` executes the frame, and `guest_sdk` runs the padding, the block
/// loop and the sixteen calls a compression takes.
///
/// **One call is four rounds**, and a compression is [`GROUPS`] calls on one
/// frame: call `r` runs rounds `4r..4r + 4` with the window's first four words
/// as their schedule words, derives the next four schedule words from the
/// window, shifts the window by four and rewrites the eight working variables.
/// The frame is ordinary RAM, so the global memory multiset is what proves call
/// `r`'s output is call `r + 1`'s input, and the guest's own loop supplies `r`.
/// After the last call the frame's state words are the working variables after
/// round 63, which the caller adds to the chaining state it kept.
///
/// `docs/spec/delegation.md` §15 is the frame table. FIPS 180-4 is the
/// algorithm, and `crates/constants/tests/sha256.rs` **re-derives** both tables
/// from their generators — the fractional parts of the square roots of the first
/// eight primes and the cube roots of the first sixty-four — in exact integer
/// arithmetic rather than trusting the transcription.
pub mod sha256 {
    /// Words of chaining state, and of working variables `a..h`.
    pub const STATE_WORDS: usize = 8;

    /// Words of one 64-byte block, big-endian decoded: the schedule's first
    /// sixteen, and the width of the frame's window.
    pub const BLOCK_WORDS: usize = 16;

    /// Rounds of the compression function.
    pub const ROUNDS: usize = 64;

    /// Rounds one call runs.
    pub const ROUNDS_PER_CALL: usize = 4;

    /// Calls one compression takes, and the values the group word may hold.
    pub const GROUPS: usize = ROUNDS / ROUNDS_PER_CALL;

    /// Frame word 0: the round group `r` in `0..GROUPS`, read and written back
    /// unchanged. The guest's loop advances it.
    pub const GROUP_WORD: usize = 0;

    /// Frame words 1..9: the working variables `a, b, c, d, e, f, g, h`, read
    /// before the call's four rounds and written after them.
    pub const STATE_WORD: usize = 1;

    /// Frame words 9..25: the schedule window `W_{4r}..W_{4r+15}`. A call reads
    /// all sixteen and writes them back shifted by four, the last four being
    /// the schedule words it derived. Call 0's window is the block.
    pub const WINDOW_WORD: usize = STATE_WORD + STATE_WORDS;

    /// The frame, in 32-bit words.
    pub const FRAME_WORDS: usize = WINDOW_WORD + BLOCK_WORDS;

    /// The frame, in bytes.
    pub const FRAME_BYTES: usize = 4 * FRAME_WORDS;

    /// The initial hash value `H0..H7`: the first 32 bits of the fractional
    /// parts of the square roots of the first eight primes. **The guest's**,
    /// not the circuit's — a compression takes its chaining state from the
    /// frame, so this is here for `guest_sdk` and the fixture guest alone.
    pub const IV: [u32; STATE_WORDS] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    /// The round constants `K[0..64]`: the first 32 bits of the fractional
    /// parts of the cube roots of the first sixty-four primes.
    pub const ROUND_CONSTANTS: [u32; ROUNDS] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
}

/// The elliptic-curve point addition, frozen at S26c.
///
/// One **complete** addition in homogeneous projective coordinates, by
/// Renes-Costello-Batina 2015 Algorithm 7 for `a = 0` — the formula
/// `guests/vendor/k256` already uses, which is why the delegation is
/// projective and not affine. Complete means no exceptional case: `P + P`,
/// `P + (-P)`, `P + O` and a non-normalized `Z` all come out right, so the
/// guest branches on nothing and the circuit has no degenerate row.
///
/// **Three invocations make one addition**, and the frame is the scratch they
/// pass intermediates through (`docs/spec/delegation.md` §16). The alternative
/// — nine reductions on one row — is 19,316 committed columns and 28.9 GiB of
/// peak a shard; three rows of three reductions is a computed 20.5 GB a shard at
/// `2^16` — above an execution shard's ~11 GB, and second now only to
/// `KECCAK_F`'s ~60 GB at the `2^18` S26d's reshape let it take.
pub mod ec_add {
    /// Limbs in a coordinate: eight 32-bit little-endian words.
    pub const LIMBS: usize = 8;

    /// Selector: secp256k1, the first group of reductions.
    pub const SECP256K1_G1: u32 = 1;
    /// Selector: secp256k1, the second group.
    pub const SECP256K1_G2: u32 = 2;
    /// Selector: secp256k1, the third group.
    pub const SECP256K1_G3: u32 = 3;
    /// Selector: BN254 G1, the first group.
    pub const BN254_G1: u32 = 4;
    /// Selector: BN254 G1, the second group.
    pub const BN254_G2: u32 = 5;
    /// Selector: BN254 G1, the third group.
    pub const BN254_G3: u32 = 6;

    /// Every selector code, ascending. **Codes start at 1**, as
    /// [`super::mod_mul::CODES`] does and for the same reason: a live row
    /// whose selector word is 0 — a caller that built a frame and forgot it —
    /// then satisfies no selector and is unprovable, where a 0-based code
    /// would have silently meant secp256k1's first group.
    pub const CODES: [u32; 6] = [
        SECP256K1_G1,
        SECP256K1_G2,
        SECP256K1_G3,
        BN254_G1,
        BN254_G2,
        BN254_G3,
    ];

    /// The curve each code names, as an index into [`CURVE_MODULI`].
    pub const CODE_CURVE: [usize; CODES.len()] = [0, 0, 0, 1, 1, 1];

    /// The group of three reductions each code names, `0..3`.
    pub const CODE_GROUP: [usize; CODES.len()] = [0, 1, 2, 0, 1, 2];

    /// Invocations one complete addition takes.
    pub const GROUPS: usize = 3;

    /// The two curves' base-field moduli, little-endian limbs, indexed by
    /// [`CODE_CURVE`]: secp256k1's `p = 2^256 - 2^32 - 977`, then BN254's `q`.
    ///
    /// They are `super::mod_mul::MODULI`'s first and third entries, and
    /// `crates/constants/tests/moduli.rs` holds them equal rather than letting
    /// a second transcription drift.
    pub const CURVE_MODULI: [[u32; LIMBS]; 2] =
        [super::mod_mul::MODULI[0], super::mod_mul::MODULI[2]];

    /// `b3 = 3b`, the one curve constant the formula reads: 21 for
    /// secp256k1's `b = 7`, 9 for BN254's `b = 3`. The curve's `a` is 0 on
    /// both and never appears.
    pub const CURVE_B3: [u32; 2] = [21, 9];

    /// Frame word 0: the selector, one of [`CODES`].
    pub const SELECTOR_WORD: usize = 0;
    /// Frame word 1: `X1`, and where `X3` is written back.
    pub const X1_WORD: usize = SELECTOR_WORD + 1;
    /// `Y1`, and where `Y3` is written back.
    pub const Y1_WORD: usize = X1_WORD + LIMBS;
    /// `Z1`, and where `Z3` is written back.
    pub const Z1_WORD: usize = Y1_WORD + LIMBS;
    /// `X2`.
    pub const X2_WORD: usize = Z1_WORD + LIMBS;
    /// `Y2`.
    pub const Y2_WORD: usize = X2_WORD + LIMBS;
    /// `Z2`.
    pub const Z2_WORD: usize = Y2_WORD + LIMBS;
    /// `xx = X1*X2`, written by group 0 and read by groups 1 and 2.
    pub const XX_WORD: usize = Z2_WORD + LIMBS;
    /// `yy = Y1*Y2`.
    pub const YY_WORD: usize = XX_WORD + LIMBS;
    /// `zz = Z1*Z2`.
    pub const ZZ_WORD: usize = YY_WORD + LIMBS;
    /// `m4 = (X1+Y1)*(X2+Y2)`, written by group 1 and read by group 2.
    pub const M4_WORD: usize = ZZ_WORD + LIMBS;
    /// `m5 = (Y1+Z1)*(Y2+Z2)`.
    pub const M5_WORD: usize = M4_WORD + LIMBS;
    /// `m6 = (X1+Z1)*(X2+Z2)`.
    pub const M6_WORD: usize = M5_WORD + LIMBS;

    /// The frame, in 32-bit words.
    pub const FRAME_WORDS: usize = M6_WORD + LIMBS;

    /// The frame, in bytes.
    pub const FRAME_BYTES: usize = 4 * FRAME_WORDS;

    /// The [`CODES`] index of `code`, or `None` for a selector word no code
    /// names.
    ///
    /// A `const fn` and a search rather than `code - 1`, so the table stays the
    /// one authority on which codes exist: a later curve appended out of order
    /// must not silently become a different group.
    pub const fn code_index(code: u32) -> Option<usize> {
        let mut i = 0;
        while i < CODES.len() {
            if CODES[i] == code {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// The modulus `code` selects.
    pub const fn modulus(code: u32) -> Option<[u32; LIMBS]> {
        match code_index(code) {
            Some(i) => Some(CURVE_MODULI[CODE_CURVE[i]]),
            None => None,
        }
    }

    /// The `b3 = 3b` that `code` selects.
    pub const fn b3(code: u32) -> Option<u32> {
        match code_index(code) {
            Some(i) => Some(CURVE_B3[CODE_CURVE[i]]),
            None => None,
        }
    }

    /// The group of three reductions `code` selects, `0..GROUPS`.
    pub const fn reduction_group(code: u32) -> Option<usize> {
        match code_index(code) {
            Some(i) => Some(CODE_GROUP[i]),
            None => None,
        }
    }

    /// The code naming `curve`'s `group`, or `None` for a pair no code names.
    ///
    /// The inverse of [`CODE_CURVE`] and [`CODE_GROUP`], by search over the
    /// same tables, so they stay the one authority in both directions. A
    /// caller performing a whole addition wants the three codes of one curve
    /// in group order and should not derive them from [`CODES`]' happening to
    /// be grouped that way.
    pub const fn group_code(curve: usize, group: usize) -> Option<u32> {
        let mut i = 0;
        while i < CODES.len() {
            if CODE_CURVE[i] == curve && CODE_GROUP[i] == group {
                return Some(CODES[i]);
            }
            i += 1;
        }
        None
    }

    /// secp256k1's three codes, in group order: the sequence one complete
    /// addition's three invocations carry.
    pub const SECP256K1_GROUPS: [u32; GROUPS] = [SECP256K1_G1, SECP256K1_G2, SECP256K1_G3];

    /// BN254 G1's three codes, in group order.
    pub const BN254_GROUPS: [u32; GROUPS] = [BN254_G1, BN254_G2, BN254_G3];

    // The two triples are literals so a caller gets them without a search,
    // and [`group_code`] is what says they are the right literals: a code
    // renumbered in [`CODES`] without its triple following fails the build
    // rather than sending group 1's operands through group 2's formula.
    const _: () = assert!(matches!(group_code(0, 0), Some(c) if c == SECP256K1_GROUPS[0]));
    const _: () = assert!(matches!(group_code(0, 1), Some(c) if c == SECP256K1_GROUPS[1]));
    const _: () = assert!(matches!(group_code(0, 2), Some(c) if c == SECP256K1_GROUPS[2]));
    const _: () = assert!(matches!(group_code(1, 0), Some(c) if c == BN254_GROUPS[0]));
    const _: () = assert!(matches!(group_code(1, 1), Some(c) if c == BN254_GROUPS[1]));
    const _: () = assert!(matches!(group_code(1, 2), Some(c) if c == BN254_GROUPS[2]));

    /// Limbs of a quotient. Group 2's operands are bounded linear combinations
    /// of canonical values rather than canonical values themselves — the worst
    /// is `byz3 <= 63m` against `xz <= 3m` — and every slot's identity carries
    /// [`OFFSET_MULTIPLE`] copies of `m^2` to keep the quotient non-negative,
    /// so the quotient reaches about `1697m` at [`OFFSET_MULTIPLE`]'s 1024 and
    /// needs a ninth limb — which nine limbs cover with room to spare, `1697m`
    /// being under `2^267`. `constraints::ec_add`'s
    /// `the_offset_covers_every_slot` and `the_carry_offset_covers_every_slot`
    /// compute the two bounds rather than trusting this sentence, and
    /// `crates/checker/tests/ec_add.rs` asserts the quotient fits nine limbs on
    /// the widest row the family admits.
    pub const QUOTIENT_LIMBS: usize = LIMBS + 1;

    /// Positions in the limb identity: `q * m` is the widest product, at
    /// `QUOTIENT_LIMBS + LIMBS - 1`.
    pub const POSITIONS: usize = QUOTIENT_LIMBS + LIMBS - 1;

    /// Carries in the limb identity: one fewer than [`POSITIONS`], the last
    /// position having no outgoing carry.
    pub const CARRIES: usize = POSITIONS - 1;

    /// Copies of `m^2` every slot's identity adds to its left-hand side.
    ///
    /// **It is one literal for every group, and that is deliberate.** A
    /// group-dependent offset would be `sum_g offset_g * g_sel * m_i * m_j`,
    /// which is degree 3; one literal keeps it degree 2 and costs the first two
    /// groups nothing but a slightly larger honest quotient. What it buys is an
    /// **unsigned** quotient: a signed one cannot take a `live`-gated offset of
    /// `256*m` without going degree 3, `m` being a column rather than a
    /// literal.
    ///
    /// **1024 and not 256, and the difference is a soundness-adjacent
    /// completeness bug S26c shipped and caught.** The binding slot is group
    /// 2's `Y3`, not its `X3`: `yp*ym + bxx9*xz` with `yp` up to `22m`, `ym`
    /// down to `-21m`, `bxx9` up to `63m` and `xz` down to `-2m` reaches
    /// **`-673 m^2`** — the operand ceilings' products, `22*22 + 63*3`. At an
    /// offset of 256 the honest quotient of such a row is *negative* and the row
    /// is unprovable, and the frames that do it are ordinary: `zz` above about
    /// `0.76m` is enough on its own, which is roughly a quarter of random
    /// invocations. Nothing in the executor or the emulator can see it — both
    /// compute the right answer — so what found it is
    /// `crates/checker/tests/ec_add.rs`' widest honest row, and what keeps it
    /// found is `constraints::ec_add`'s `the_offset_covers_every_slot`, which
    /// derives this floor from the same ceiling table the carry bound uses.
    pub const OFFSET_MULTIPLE: u64 = 1024;

    /// A signed carry's offset, as a bit position: the carry spans
    /// `[-2^46, 2^46)`, so `u = c + 2^46` spans `[0, 2^46)`.
    ///
    /// **Derived, and the derivation moved it twice.** The widest position is
    /// group 2's `Y3`, whose left-hand side is `yp*ym + bxx9*xz` at
    /// `22*22 + 63*3` multiples of `m^2` plus [`OFFSET_MULTIPLE`] more — 1,697
    /// of them since that constant rose to 1024 — so a position reaches `2^78`
    /// and the carry's fixed point `2^46`. It read 44 when the offset was
    /// guessed, 45 when the positions were derived, and 46 once the offset had
    /// to cover `-673 m^2`. `constraints::ec_add`'s
    /// `the_carry_offset_covers_every_slot` recomputes it from the operand
    /// ceilings rather than trusting this paragraph.
    pub const CARRY_OFFSET_BITS: u32 = 46;

    /// A carry's unsigned range, in bits: one more than
    /// [`CARRY_OFFSET_BITS`].
    pub const CARRY_BITS: u32 = CARRY_OFFSET_BITS + 1;
}

pub mod mod_mul {
    /// Limbs per 256-bit value: eight 32-bit words, little-endian.
    pub const LIMBS: usize = 8;

    // -----------------------------------------------------------------------
    // The modulus selector
    // -----------------------------------------------------------------------

    /// secp256k1's base field, `p = 2^256 - 2^32 - 977`. The field a mainnet
    /// block spends most of its `ecrecover` cycles in.
    pub const SECP256K1_P: u32 = 1;
    /// secp256k1's scalar field, the group order `n`.
    pub const SECP256K1_N: u32 = 2;
    /// BN254's base field, `q` — the coordinate field of the `0x06`, `0x07`
    /// and `0x08` precompiles' curve. [`crate::FQ_MODULUS`] is the same
    /// number in four 64-bit limbs.
    pub const BN254_P: u32 = 3;
    /// BN254's scalar field, `r` — this VM's own `Fr`.
    /// [`crate::FR_MODULUS`] is the same number in four 64-bit limbs.
    ///
    /// It is **not** [`super::family::FR_ARITH`]'s duplicate: that family
    /// multiplies Montgomery representatives and this one multiplies plain
    /// integers, so a caller holding arkworks' `Fp256` reaches this one and a
    /// caller holding `field::Fr` reaches that one.
    pub const BN254_R: u32 = 4;

    /// The modulus codes, ascending, in selector order. A live row's selector
    /// word is exactly one of these; the circuit's selector column `i` is this
    /// entry's, and [`MODULI`]`[i]` is the modulus it names.
    ///
    /// **Codes start at 1, not 0**, for the reason
    /// [`super::fr_arith::OPS`] does: a live row whose selector word is 0 —
    /// a caller that built a frame and forgot the modulus — then satisfies no
    /// selector and is unprovable, where a 0-based code would have silently
    /// meant secp256k1's `p`.
    pub const CODES: [u32; 4] = [SECP256K1_P, SECP256K1_N, BN254_P, BN254_R];

    /// The four moduli, eight little-endian 32-bit limbs each, in [`CODES`]
    /// order. The circuit's selector picks one of these by literal.
    ///
    /// `crates/constants/tests/moduli.rs` holds all four against
    /// `crates/constants/tests/vectors/moduli.txt`, which `kat-gen` writes
    /// from arkworks' own `ark-secp256k1` and `ark-bn254` — so none of these
    /// numbers is trusted as a transcription. The same test re-derives
    /// [`SECP256K1_P`]'s value as `2^256 - 2^32 - 977` and the two BN254
    /// entries from [`crate::FQ_MODULUS`] and [`crate::FR_MODULUS`].
    pub const MODULI: [[u32; LIMBS]; CODES.len()] = [
        // secp256k1 p = 2^256 - 2^32 - 977
        [
            0xffff_fc2f,
            0xffff_fffe,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
        ],
        // secp256k1 n, the group order
        [
            0xd036_4141,
            0xbfd2_5e8c,
            0xaf48_a03b,
            0xbaae_dce6,
            0xffff_fffe,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
        ],
        // BN254 q, the base field
        [
            0xd87c_fd47,
            0x3c20_8c16,
            0x6871_ca8d,
            0x9781_6a91,
            0x8181_585d,
            0xb850_45b6,
            0xe131_a029,
            0x3064_4e72,
        ],
        // BN254 r, the scalar field
        [
            0xf000_0001,
            0x43e1_f593,
            0x79b9_7091,
            0x2833_e848,
            0x8181_585d,
            0xb850_45b6,
            0xe131_a029,
            0x3064_4e72,
        ],
    ];

    /// `R^-1 mod q` for BN254's base field, `R = 2^256`, eight little-endian
    /// 32-bit limbs.
    ///
    /// **A caller-side constant, not the circuit's.** The delegation computes
    /// a plain product; a caller holding **Montgomery** representatives —
    /// arkworks' `Fp256` is the one in this repository's guest tree — wants
    /// `a·b·R^-1`, which is this delegation twice: the plain product, then
    /// that by `R^-1`. Two calls at ~90 cycles each against one software
    /// Montgomery multiply at ~2,000. `guests/vendor/ark-ff` is the caller.
    ///
    /// secp256k1 has no sibling constant because `k256` stores plain
    /// residues, so its multiply is one call and needs no correction.
    pub const BN254_P_R_INV: [u32; LIMBS] = [
        0x014a_fa37,
        0xed84_884a,
        0x0278_edf8,
        0xeb20_2285,
        0xb744_92d9,
        0xcf63_e9cf,
        0x59e5_c639,
        0x2e67_1571,
    ];

    /// `R^-1 mod r` for BN254's scalar field. [`BN254_P_R_INV`]'s sibling, and
    /// the inverse of [`crate::FR_R`].
    pub const BN254_R_R_INV: [u32; LIMBS] = [
        0x6db1_194e,
        0xdc5b_a005,
        0xe111_ec87,
        0x090e_f5a9,
        0xaeb8_5d5d,
        0xc826_0de4,
        0x82c5_551c,
        0x15eb_f951,
    ];

    /// The limbs [`CODES`] entry `code` names, or `None` for a code no live
    /// row may carry.
    ///
    /// The one lookup, so the executor, the fill and the circuit read the
    /// table the same way and an unrecognized code is a `None` somebody has
    /// to handle rather than a silent default.
    pub const fn modulus(code: u32) -> Option<&'static [u32; LIMBS]> {
        let mut i = 0;
        while i < CODES.len() {
            if CODES[i] == code {
                return Some(&MODULI[i]);
            }
            i += 1;
        }
        None
    }

    // -----------------------------------------------------------------------
    // The frame
    // -----------------------------------------------------------------------

    /// The selector word: which of [`CODES`] this row multiplies under.
    pub const SELECTOR_WORD: usize = 0;

    /// The first word of operand `a`, which must be below the modulus.
    pub const A_WORD: usize = SELECTOR_WORD + 1;

    /// The first word of operand `b`, which must be below the modulus.
    pub const B_WORD: usize = A_WORD + LIMBS;

    /// The first word of the result. The only words the invocation writes.
    pub const OUT_WORD: usize = B_WORD + LIMBS;

    /// The frame: the selector, then three values of eight limbs.
    pub const FRAME_WORDS: usize = OUT_WORD + LIMBS;

    /// The frame in bytes, which is what a shim hands over.
    pub const FRAME_BYTES: usize = 4 * FRAME_WORDS;

    // -----------------------------------------------------------------------
    // The limb identity's bounds
    // -----------------------------------------------------------------------

    /// Positions of the schoolbook identity: `a*b` and `q*m` each have limb
    /// products at `i + j` for `i, j < LIMBS`, so `0 ..= 2*LIMBS - 2`.
    pub const POSITIONS: usize = 2 * LIMBS - 1;
    /// The carries the identity needs: one out of every position but the last,
    /// whose outgoing carry the identity forces to zero.
    pub const CARRIES: usize = POSITIONS - 1;

    /// Bits a signed carry takes, offset included.
    ///
    /// **Derived, not chosen.** At position `k` the identity is
    /// `P_k - S_k - out_k + c_{k-1} = 2^32 * c_k`, where `P_k` and `S_k` are
    /// each at most `LIMBS` products of two values below `2^32` — so under
    /// `8 * 2^64 = 2^67` — and `out_k` is under `2^32`. Writing `C` for the
    /// bound on `|c|`, the recurrence is
    /// `C = (2^67 + 2^32 + C) / 2^32`, whose fixed point is just above `2^35`.
    /// [`CARRY_OFFSET`] is `2^36` and a carry is written as
    /// `sum of bits - CARRY_OFFSET`, so the bits span `[-2^36, 2^36)` — a full
    /// factor of two of room over the bound.
    ///
    /// **The selector does not tighten it.** Every limb of `m`, `a`, `b` and
    /// `q` is still bounded only by `2^32`, which is what this arithmetic
    /// reads; fixing the modulus changes no term of it.
    pub const CARRY_BITS: usize = 37;
    /// The offset a carry's bit decomposition carries: `2^36`.
    pub const CARRY_OFFSET: u64 = 1 << (CARRY_BITS - 1);
}
