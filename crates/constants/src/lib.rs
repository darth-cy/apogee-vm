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
    /// `crates/program/CLAUDE.md`.
    pub const PROGRAM_IDENTITY: u64 = 22;

    /// Scalars. The static `VmConfig`: the family ids in ascending order, then
    /// their heights in the same order, then `bytecode_size_words`. The first
    /// half of the statement descriptor, and the second message of the
    /// program-identity sponge.
    pub const VM_CONFIG: u64 = 23;

    /// Scalars. The per-proof shard count of every family in the `VmConfig`,
    /// in the same ascending order. The second half of the statement
    /// descriptor, always absorbed immediately after the [`VM_CONFIG`]
    /// message it counts shards for.
    pub const SHARD_COUNTS: u64 = 24;
}

/// The circuit families, by number. Frozen at S11; **append-only**.
///
/// A family is one arithmetization shape covering a set of program counters.
/// The number is what every later stage cites: canonical ordering is ascending
/// `FamilyId`, the program-identity digest absorbs families in that order, and
/// shard transcripts are seeded with it. Delegation families are appended
/// after [`INIT_TEARDOWN`] and never renumber anything below them.
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
    /// Memory initialisation and teardown. Claims no pc; present in every
    /// `VmConfig`.
    pub const INIT_TEARDOWN: u32 = 7;

    /// How many families this table defines.
    pub const COUNT: u32 = 8;

    /// The trace-height menu, ascending. Even powers of two only, so that a
    /// Mercury opening's `b = sqrt(n)` exists.
    pub const HEIGHT_MENU: [u32; 4] = [1 << 16, 1 << 18, 1 << 20, 1 << 22];

    /// The default trace height of every family, indexed by `FamilyId`.
    pub const DEFAULT_HEIGHTS: [u32; COUNT as usize] = [
        1 << 22, // ADD_SUB_LUI_AUIPC
        1 << 22, // JUMP_BRANCH_SLT
        1 << 22, // SHIFT_BITWISE
        1 << 20, // MUL_DIV
        1 << 22, // MEM_WORD
        1 << 22, // MEM_SUBWORD
        1 << 16, // ATOMICS
        1 << 20, // INIT_TEARDOWN
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
}

/// The guest ecall ABI: syscall numbers, range boundaries and file
/// descriptors, in one place forever.
///
/// **Append-only.** Once a program's identity is published its ABI is frozen.
/// Redefining a number does not fail loudly — it quietly makes an old program
/// compute something else — so numbers here are assigned once and never
/// reused, exactly like `transcript_tags`.
///
/// An ecall follows the Linux RISC-V convention: number in `a7`, arguments in
/// `a0`-`a5`, return in `a0`, errors as the negated errno. The standard subset
/// keeps its Linux numbers so `qemu-riscv32` runs guests unmodified; the two
/// non-Linux ranges sit above every Linux number and are disjoint from each
/// other. `docs/spec/ecall-abi.md` is the normative table.
pub mod ecall {
    /// Linux `read`. zkVM meaning is per file descriptor: see [`FD_PUBLIC_INPUT`]
    /// and [`FD_HINT`].
    pub const READ: u32 = 63;

    /// Linux `write`. zkVM meaning is per file descriptor: see
    /// [`FD_PUBLIC_OUTPUT`] and [`FD_STDERR`].
    pub const WRITE: u32 = 64;

    /// Linux `exit`. `a0` is the exit status; a nonzero status is a failed
    /// execution.
    pub const EXIT: u32 = 93;

    /// First number of the zkVM-specific host-call range, `0x0400..=0x04FF`.
    ///
    /// Reserved and empty at S10. Calls here are **nondeterministic prover
    /// advice**: whatever the host returns is a value the prover chose, and it
    /// binds nothing unless it is folded into the public I/O digest. Kept
    /// disjoint from [`PRECOMPILE_FIRST`] precisely so a reviewer can tell the
    /// two apart at a glance.
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

    /// Poseidon2 permutation over a `[Fr; 3]` state, `a0` = state pointer.
    ///
    /// The one precompile number S10 assigns. No circuit implements it yet, so
    /// every executor answers `-ENOSYS` and the caller runs its software path.
    pub const PRECOMPILE_POSEIDON2: u32 = 0x0500;

    /// Public input, committed: the fd 0 byte stream the public I/O digest
    /// binds first.
    pub const FD_PUBLIC_INPUT: u32 = 0;

    /// Public output / journal, committed: the fd 1 byte stream the public I/O
    /// digest binds second.
    pub const FD_PUBLIC_OUTPUT: u32 = 1;

    /// Diagnostics. Free-form, uncommitted, and ignored by the verifier.
    pub const FD_STDERR: u32 = 2;

    /// Private hint channel, uncommitted: nondeterministic prover advice. A
    /// guest that lets a hint change its committed output has made the proof
    /// meaningless, because the prover picks the hint.
    pub const FD_HINT: u32 = 3;

    /// Linux `ENOSYS`. An unimplemented number returns `-ENOSYS` in `a0`.
    pub const ENOSYS: u32 = 38;

    /// Linux `EBADF`. `read` on a descriptor other than [`FD_PUBLIC_INPUT`]
    /// and [`FD_HINT`], and `write` on one other than [`FD_PUBLIC_OUTPUT`] and
    /// [`FD_STDERR`], return `-EBADF` in `a0` — Linux's answer, and so
    /// `qemu-riscv32`'s. Added at S12.
    pub const EBADF: u32 = 9;
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
}

/// The memory argument's clock, frozen at S12 from the master's memory
/// invariant.
///
/// Cycle `c` occupies timestamps `TS_STEP * c + delta` for the four in-cycle
/// slots `delta` in `0..TS_STEP`. Timestamp 0 is the initial write of every
/// address, so the first executed cycle is **cycle 1**: a cycle-0 pc query
/// would write at timestamp 0 and could not strictly follow the initial write
/// it reads. Every timestamp is below `2^TS_BITS`.
pub mod memory {
    /// Timestamps per cycle, one per in-cycle slot.
    pub const TS_STEP: u64 = 4;
    /// The width of a timestamp, in bits.
    pub const TS_BITS: u32 = 38;
}
