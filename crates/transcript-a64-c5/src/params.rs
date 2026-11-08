//! Poseidon2-A64-C5's constants, value for value and in order as HorizenLabs'
//! `poseidon2_rust_params.sage` prints them at commit `055bde3`, edited only at
//! `p`, `t` and `R_F` (`docs/spec/transcript.md` §1.2; the run is `docs/tools.md`
//! §8). Generated, never edited: `tests/permutation.rs` holds the permutation
//! they key to the generator's own answer at `[0, 1, …, 15]`.

/// `μ_i − 1` for the internal matrix `M_I = J + diag(μ − 1)`: `MAT_DIAG16_M_1`.
#[rustfmt::skip]
pub(crate) const INTERNAL_DIAG_M_1: [u64; 16] = [
    0x8c10a8ce5034e7e8, 0x1931fc0383e50211, 0x28a06de917b5d352, 0xde5501ea0f11990f,
    0x913b96b19d26392d, 0x8e47a0e65a05faf5, 0x80d19f2bb9d0fbb9, 0xc2ced79b54e7316a,
    0xaa2a5e9d40524eb4, 0xf604423d63ed4f6e, 0xc7e8f0e92efb8b44, 0x9b329edf06deff59,
    0x465217a0ebca4c1b, 0x56311fe256fa128f, 0x17a9d46b512d7804, 0x30e56eedd3c99289,
];

/// The 6 initial full rounds' constants: `RC16` rows 0..6.
#[rustfmt::skip]
pub(crate) const RC_INITIAL: [[u64; 16]; 6] = [
    [
        0x7047c3dc92736be8, 0x4493a8148a6f85ca, 0xaa60e3cde94e1752, 0x9e868d333548f562,
        0xafb5da41ea86af6c, 0x3640076df46fa9aa, 0x785a94c5ac04eb8d, 0x0c6498cbd5e2756f,
        0x2ab1c8083c056bf6, 0x3025f57d43c7b82a, 0x24c3d60fb40045ae, 0xc084235576b7920a,
        0xd11b2f79642586b8, 0x63a14204a158a1df, 0xe9e8e3fb5f2372d5, 0xb5c744f0f8adf8ce,
    ],
    [
        0x8841ceb2663bf698, 0x1a6200674f23a7f1, 0x89b3f9918dce930b, 0x39f476b0c95ac243,
        0x22d4b17ba98cc6e7, 0x74eb860a60fc142c, 0x55dc3dd52a793c13, 0x8a8048133ffd8a25,
        0x789e9cf21d9e1715, 0x40a637ab67b5aa9d, 0xfa7b127c1135e2e3, 0x7046a3936101d50e,
        0x07580b9720662d51, 0x8c401a60da88834f, 0x003016b03062520f, 0x67142dabeba7687b,
    ],
    [
        0x4b5d16d072172d6c, 0xfd35431f2d69d48e, 0x987a1441571589de, 0x9134f9b4bd1594da,
        0x7a9b6fb03c5c2962, 0x3b291c38b7edd9b9, 0x24931e69038b728d, 0x339c23001c614132,
        0xa98f4b79d34f265a, 0x821127f3072b6cf3, 0x214381bfd649e69b, 0x750a7869b93d8984,
        0xce8ac028aa6d34c7, 0xfdd95e5b3d86c657, 0xdb92c09767eea4d3, 0x01f21817ebf66c2f,
    ],
    [
        0x7aca4f6765c1e105, 0x4ebfcebc9634eeb5, 0x23b3eef3d59f2166, 0xe4c2dbdfc2e3e9e8,
        0x258e3d922a4b03ee, 0xdff083155c0fc28b, 0x28617062f92168ea, 0x04f0e53af046c649,
        0x8f8f74b0a4abae33, 0xf0e2e98381e99875, 0xeb4eff03a2682e29, 0xa0055d24fba968cd,
        0xb1cec5c313d84751, 0xef7655f4987cf404, 0xcdd1bbc7391c086f, 0xdbec6998cd68a80f,
    ],
    [
        0xbfef9492a6e6192b, 0x8c4141c123487ba5, 0xa54f4abf6c6e0552, 0xf710588192b9284e,
        0x70bef2935d0acef8, 0x53211acdd552a5f6, 0xef2fca1b25eab2dc, 0x2081f0277d8167e0,
        0x685a09e92794ed36, 0xe29cc173d5373fac, 0x2749d6757b198213, 0x9d4d74709a367a2a,
        0xc092b54fe1655479, 0x4112c0c934c109cc, 0xa9ae7703d7ce37da, 0x295180cb458087ee,
    ],
    [
        0x65c3ff6c9f07b89b, 0x2dcefb7ae8af32ad, 0x53b232e84dc95ab0, 0x3b296bdca82908af,
        0x22472c00e68d68b7, 0x3a93373a4d71d610, 0x4efe9f02230015c5, 0xc142e21311370345,
        0x3b25e29c5a5cf8c5, 0x394a449627b021e7, 0x05bc705ee1bedf16, 0x4ae02b950fb9d7c6,
        0x88df86d112f7a18f, 0xa7c4f5f0fd1d06e0, 0x6e4119b73e2fedba, 0x49fafc501c2cedc4,
    ],
];

/// The 42 partial rounds' constants: lane 0 of `RC16` rows 6..48, whose lanes
/// 1..16 the generator prints as zero.
#[rustfmt::skip]
pub(crate) const RC_PARTIAL: [u64; 42] = [
    0xcc437af88bbc0fa4, 0xf0a621c4752bdcdf, 0xcd77843261a3d77d, 0x1f0e8c1f92705922,
    0x6d9d9f0da8042761, 0x26d4b4ce501b92c8, 0x0ce8adb236fbd227, 0xbc29af81a0edcf83,
    0x6c88dea317938d36, 0x7aca51f495edffca, 0x6671b2c701e764a6, 0x843fa7a64dd4a931,
    0x34e275bda3984a9d, 0x4ca92812ad89f96a, 0x1d453072915ce8b5, 0x17eaf2f33ff4696e,
    0x2ae093012dcfaf50, 0x960799ac3f64a26d, 0x9249961472410929, 0x3efd5875220115d6,
    0x4ad33e50fcf28800, 0x2947729a976f4640, 0xf7b8501bdd7fecae, 0xd2820fdb1125e1c4,
    0xbee18d4f1faa1c5d, 0x8a12dc23ebbb624d, 0x9a88a574e9a5d1a1, 0xd9618bfc06c34237,
    0x5b8e74f87df39ebe, 0x01726b7266ed0a1c, 0xd913a49f91add3db, 0x6fe213c90004b238,
    0xf369cd3786d834cf, 0x81651049d3bbf44b, 0x728fe04ac8bd27e7, 0x760149424519aae3,
    0xcc151807658ffbd7, 0xef5a05fd98da42f7, 0x783abe8ec6bc1142, 0xc00ac779ccd5ebab,
    0x589ec82758720308, 0xfd00cf0b5de1777f,
];

/// The 6 terminal full rounds' constants: `RC16` rows 48..54.
#[rustfmt::skip]
pub(crate) const RC_TERMINAL: [[u64; 16]; 6] = [
    [
        0x08d6ecaabd6f14e4, 0xd12d4f88cc7da760, 0xd4ef6925e221b290, 0xc324c3c0ae15d53c,
        0xc6f882c1f9fd30a4, 0x31662cdab9b4e735, 0x5f2067d276827b46, 0x588cf7b2490a348e,
        0x31b16cdf0d50c5eb, 0x5c0243180fafd3b2, 0xfa72734258fab521, 0x65e297e796a54f51,
        0x9a68ece0a22e26bc, 0x8e7615315ac51c90, 0x229acf1a7e925152, 0xf64dd4532e540a39,
    ],
    [
        0x62ae031cf7a7d995, 0x5e34b48d1e962bf7, 0xa2b5b361403041ba, 0x8288735c528d99e2,
        0xd0ee5943d1b14363, 0x2301d5fc0917b286, 0x7e9f5a70d3249531, 0xde85c17d19b453cd,
        0xc1e0e752a6a689e3, 0x2324dcfeebef4ff8, 0xee25cb5533b2c207, 0x26da424af5e7ea36,
        0xd1217659c2585c40, 0x1bbcb9c8e4f7d654, 0x1b937902864e3ae1, 0xb8720228358cf562,
    ],
    [
        0xdac70675806d0815, 0x272bd4dd369b391e, 0x1fb7513d441421f9, 0x16ef5200d3f55fd4,
        0xbf3268bcaf09bc1f, 0x317f01a7bd98bfbc, 0x2fcca518b59f92b3, 0xc6ef11fd798fdfd8,
        0x222540acb83348e7, 0xea31ace636446ee3, 0xd93ac783c2cc080f, 0x64f1e2ba0c16303d,
        0x71ea3b96ba39b249, 0x2f0a03c8bad7aded, 0xe1e0b81894cefe02, 0xf60f1d58edc555c7,
    ],
    [
        0x712dea3d3c682cf1, 0x580016de651247c9, 0xf393596a6ef02e68, 0xec115ff8a0ab2064,
        0x380b5ea2b04a2a12, 0x43b949b9011d6c75, 0x699a25d56d047b11, 0x3e092f396912fcb5,
        0x165e9c674d76a458, 0x5d15ce9a69c163ce, 0x039bff63b9c5e2af, 0x1cef1449c294fa1a,
        0x496ac40c9d7d01ca, 0xbc1c27b72416ed8a, 0x3291357bc2cf9454, 0x5f19d250ad19803c,
    ],
    [
        0x745468970f131f9e, 0x8ce512afd566b2a9, 0xffd028a7c48113e6, 0x5359cb4a9e3c8443,
        0xeb8cb2e7677f78d7, 0x464e2b31a8aa27fe, 0xc53aa7ecfb2c3a96, 0x20d5e4e411405082,
        0xa3ca0a158aec73f4, 0xa2190d708bbfa769, 0xb02df32f934c6216, 0x0f0d4731494230cc,
        0x7975b2c2945426a2, 0x8d32496b5308d589, 0x0c5967274b5b80d7, 0xcd5e81cb46aece9e,
    ],
    [
        0x80f933ac98dcb532, 0x668ee364f565c43e, 0xfd0a78bba94d272f, 0xdaff8e36ee05df53,
        0x9859ba5cbcb486fa, 0x3e71731fd4737391, 0x2cae0f202c85aac6, 0x941f5238f52a9690,
        0x69cea53aab57c457, 0xf6342424d0e21b8c, 0xeba4cf91ac60d6ab, 0x4f0d0ab2616fcc22,
        0x558c2a137c5467c1, 0x51fe2d8ed6076c81, 0xd0e2aee95b4673c5, 0xb5b7c45223d8273d,
    ],
];
