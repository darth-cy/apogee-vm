// Falcon-512 key generation, bit-exact with the Falcon round-3 reference implementation
// (Reference_Implementation/falcon512/falcon512int of the NIST round-3 package): a 48-byte seed
// goes into SHAKE256 (initialized, the seed injected, flipped), that SHAKE256 is the random source
// of keygen.c's Zf(keygen) at logn = 9, and the keys are encoded as nist.c's crypto_sign_keypair
// encodes them. The same seed gives the same keys as the reference C, byte for byte, on every
// platform: this is what lets a wallet recover a key from its seed.
//
// What is ported, and how:
//  - SHAKE256 (shake.c): our own Keccak-f[1600] on 32-bit halves; browsers have none.
//  - The sampler (mkgauss, poly_small_mkgauss) and the rejection tests of Zf(keygen), in order.
//  - Every floating-point step: the FFT and iFFT of fft.c with fpr_gm_tab copied (never
//    recomputed), the poly_* helpers in the reference's operation order, poly_big_to_fp's
//    limb-by-limb accumulation, fpr_rint (ties to even), the Babai schedule of
//    solve_NTRU_intermediate (scale_k, 25-bit steps, the top 10 words, FGlen shrinking) and the
//    reductions of solve_NTRU_binary_depth1 and _depth0. The reference's fpr type is IEEE-754
//    binary64 emulated with integers (round to nearest even, no FMA); JavaScript numbers are
//    binary64 with the same rounding, one operation at a time.
//  - The reference's multi-word integers and RNS/CRT arithmetic compute exact integers; BigInt
//    computes them here. Where the reference keeps a value in a fixed number of 31-bit words, or
//    rebuilds it modulo a product of its small primes, the same reduction is applied (asIntN,
//    smod), so even an out-of-range value goes the reference's way. The one exception is noted
//    at solveDepth0.
//
// One ES module, no dependencies, synchronous: Node.js >= 20 and browsers.

export const SEED_BYTES = 48;
const PUBLIC_KEY_BYTES = 897, SECRET_KEY_BYTES = 1281;

const LOGN = 9, N = 512, Q = 12289;

// ---------------------------------------------------------------------------------------------
// SHAKE256 (FIPS 202): rate 136 bytes, domain byte 0x1F. Lanes are (lo, hi) 32-bit pairs.
// ---------------------------------------------------------------------------------------------

const KECCAK_RC = (() => {
  const rc = `0000000000000001 0000000000008082 800000000000808A 8000000080008000 000000000000808B
    0000000080000001 8000000080008081 8000000000008009 000000000000008A 0000000000000088
    0000000080008009 000000008000000A 000000008000808B 800000000000008B 8000000000008089
    8000000000008003 8000000000008002 8000000000000080 000000000000800A 800000008000000A
    8000000080008081 8000000000008080 0000000080000001 8000000080008008`.trim().split(/\s+/);
  const out = new Uint32Array(48);
  rc.forEach((h, i) => {
    out[2 * i] = parseInt(h.slice(8), 16);
    out[2 * i + 1] = parseInt(h.slice(0, 8), 16);
  });
  return out;
})();
// Rotation of lane x + 5y, and where ρ∘π moves it: (x, y) → (y, 2x + 3y).
const KECCAK_ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const KECCAK_PI = KECCAK_ROT.map((_, i) => ((i / 5) | 0) + 5 * ((2 * (i % 5) + 3 * ((i / 5) | 0)) % 5));

const keccakC = new Uint32Array(10), keccakB = new Uint32Array(50);
function keccakF(s) {
  const c = keccakC, b = keccakB;
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 10; x++) c[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 5; x++) {
      const p = 2 * ((x + 4) % 5), r = 2 * ((x + 1) % 5);
      const lo = c[p] ^ ((c[r] << 1) | (c[r + 1] >>> 31));
      const hi = c[p + 1] ^ ((c[r + 1] << 1) | (c[r] >>> 31));
      for (let y = 0; y < 50; y += 10) {
        s[y + 2 * x] ^= lo;
        s[y + 2 * x + 1] ^= hi;
      }
    }
    for (let i = 0; i < 25; i++) {
      const lo = s[2 * i], hi = s[2 * i + 1], r = KECCAK_ROT[i], j = 2 * KECCAK_PI[i];
      if (r === 0) {
        b[j] = lo;
        b[j + 1] = hi;
      } else if (r < 32) {
        b[j] = (lo << r) | (hi >>> (32 - r));
        b[j + 1] = (hi << r) | (lo >>> (32 - r));
      } else if (r === 32) {
        b[j] = hi;
        b[j + 1] = lo;
      } else {
        b[j] = (hi << (r - 32)) | (lo >>> (64 - r));
        b[j + 1] = (lo << (r - 32)) | (hi >>> (64 - r));
      }
    }
    for (let y = 0; y < 50; y += 10) {
      for (let x = 0; x < 10; x++) {
        const x1 = y + ((x + 2) % 10), x2 = y + ((x + 4) % 10);
        s[y + x] = b[y + x] ^ (~b[x1] & b[x2]);
      }
    }
    s[0] ^= KECCAK_RC[2 * round];
    s[1] ^= KECCAK_RC[2 * round + 1];
  }
}

// SHAKE256 over `input`, read 8 bytes (one little-endian u64, as (lo, hi)) at a time: the
// reference's inner_shake256_init / _inject / _flip, then get_rng_u64's 8-byte extracts. The rate
// is 17 lanes, so every extract is one whole lane.
class Shake256 {
  constructor(input) {
    const s = (this.state = new Uint32Array(50));
    let at = 0;
    for (const byte of input) {
      s[at >> 2] ^= byte << ((at & 3) << 3);
      if (++at === 136) {
        keccakF(s);
        at = 0;
      }
    }
    s[at >> 2] ^= 0x1f << ((at & 3) << 3);
    s[33] ^= 0x80000000; // byte 135
    this.lane = 17;
    this.lo = 0;
    this.hi = 0;
  }

  next() {
    if (this.lane === 17) {
      keccakF(this.state);
      this.lane = 0;
    }
    this.lo = this.state[2 * this.lane];
    this.hi = this.state[2 * this.lane + 1];
    this.lane++;
  }
}

/** SHAKE256(input), `length` bytes: the sponge keygen draws from (exported for tests). */
export function _shake256(input, length) {
  const xof = new Shake256(input), out = new Uint8Array(length);
  for (let i = 0; i < length; i += 8) {
    xof.next();
    for (let j = 0; j < 8 && i + j < length; j++) out[i + j] = (j < 4 ? xof.lo : xof.hi) >>> ((j & 3) << 3);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The sampler: keygen.c's gauss_1024_12289 table, mkgauss (two 1024-degree samples summed at
// logn = 9) and poly_small_mkgauss (odd coefficient sum).
// ---------------------------------------------------------------------------------------------

const GAUSS = `1283868770400643928 6416574995475331444 4078260278032692663 2353523259288686585
  1227179971273316331 575931623374121527 242543240509105209 91437049221049666 30799446349977173
  9255276791179340 2478152334826140 590642893610164 125206034929641 23590435911403 3948334035941
  586753615614 77391054539 9056793210 940121950 86539696 7062824 510971 32764 1862 94 4 0`
  .trim().split(/\s+/).map(BigInt);
const GAUSS_HI = Uint32Array.from(GAUSS, (x) => Number(x >> 32n));
const GAUSS_LO = Uint32Array.from(GAUSS, (x) => Number(x & 0xffffffffn));

// r < GAUSS[k], for r = (hi, lo) and every value below 2^63.
const below = (hi, lo, k) => hi < GAUSS_HI[k] || (hi === GAUSS_HI[k] && lo < GAUSS_LO[k]);

function mkgauss(rng) {
  let val = 0;
  for (let u = 0; u < 2; u++) {
    rng.next();
    const neg = rng.hi >>> 31;
    let f = below(rng.hi & 0x7fffffff, rng.lo, 0) ? 1 : 0; // 1: the value is zero
    let v = 0;
    rng.next();
    const hi = rng.hi & 0x7fffffff, lo = rng.lo;
    for (let k = 1; k < GAUSS.length; k++) {
      const t = below(hi, lo, k) ? 0 : 1;
      if (t && !f) v = k;
      f |= t;
    }
    val += neg ? -v : v;
  }
  return val;
}

function smallGauss(rng, f) {
  let mod2 = 0;
  for (let u = 0; u < N; u++) {
    for (;;) {
      const s = mkgauss(rng);
      if (s < -127 || s > 127) continue;
      if (u === N - 1) {
        if ((mod2 ^ (s & 1)) === 0) continue;
      } else {
        mod2 ^= s & 1;
      }
      f[u] = s;
      break;
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Floating point: fpr.h's constants (bit patterns), fpr.c's fpr_gm_tab and fpr_p2_tab, fft.c.
// ---------------------------------------------------------------------------------------------

const fpr = (bits) => {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, bits);
  return view.getFloat64(0);
};
const FPR_Q = fpr(4667981563525332992n);
const FPR_BNORM_MAX = fpr(4670353323383631276n);
const FPR_ONE = fpr(4607182418800017408n), FPR_TWO = fpr(4611686018427387904n);
const FPR_ONEHALF = fpr(4602678819172646912n);
const FPR_PTWO31M1 = fpr(4746794007244308480n), FPR_MTWO31M1 = fpr(13970166044099084288n);
const FPR_PTWO63M1 = fpr(4890909195324358656n), FPR_MTWO63M1 = fpr(14114281232179134464n);
const FPR_PTWO31 = fpr(4746794007248502784n);
const FPR_P2 = [4611686018427387904n, 4607182418800017408n, 4602678819172646912n,
  4598175219545276416n, 4593671619917905920n, 4589168020290535424n, 4584664420663164928n,
  4580160821035794432n, 4575657221408423936n, 4571153621781053440n].map(fpr);

function doubles(text) {
  const words = text.trim().split(/\s+/), view = new DataView(new ArrayBuffer(8));
  return Float64Array.from(words, (w) => {
    view.setUint32(0, parseInt(w.slice(0, 8), 16));
    view.setUint32(4, parseInt(w.slice(8), 16));
    return view.getFloat64(0);
  });
}

// fpr_gm_tab: its first 512 complex entries (re, im), all that logn <= 9 reads.
const GM = doubles(`
  0000000000000000 0000000000000000 8000000000000000 3ff0000000000000 3fe6a09e667f3bcd 3fe6a09e667f3bcd bfe6a09e667f3bcd 3fe6a09e667f3bcd
  3fed906bcf328d46 3fd87de2a6aea963 bfd87de2a6aea963 3fed906bcf328d46 3fd87de2a6aea963 3fed906bcf328d46 bfed906bcf328d46 3fd87de2a6aea963
  3fef6297cff75cb0 3fc8f8b83c69a60b bfc8f8b83c69a60b 3fef6297cff75cb0 3fe1c73b39ae68c8 3fea9b66290ea1a3 bfea9b66290ea1a3 3fe1c73b39ae68c8
  3fea9b66290ea1a3 3fe1c73b39ae68c8 bfe1c73b39ae68c8 3fea9b66290ea1a3 3fc8f8b83c69a60b 3fef6297cff75cb0 bfef6297cff75cb0 3fc8f8b83c69a60b
  3fefd88da3d12526 3fb917a6bc29b42c bfb917a6bc29b42c 3fefd88da3d12526 3fe44cf325091dd6 3fe8bc806b151741 bfe8bc806b151741 3fe44cf325091dd6
  3fec38b2f180bdb1 3fde2b5d3806f63b bfde2b5d3806f63b 3fec38b2f180bdb1 3fd294062ed59f06 3fee9f4156c62dda bfee9f4156c62dda 3fd294062ed59f06
  3fee9f4156c62dda 3fd294062ed59f06 bfd294062ed59f06 3fee9f4156c62dda 3fde2b5d3806f63b 3fec38b2f180bdb1 bfec38b2f180bdb1 3fde2b5d3806f63b
  3fe8bc806b151741 3fe44cf325091dd6 bfe44cf325091dd6 3fe8bc806b151741 3fb917a6bc29b42c 3fefd88da3d12526 bfefd88da3d12526 3fb917a6bc29b42c
  3feff621e3796d7e 3fa91f65f10dd814 bfa91f65f10dd814 3feff621e3796d7e 3fe57d69348ceca0 3fe7b5df226aafaf bfe7b5df226aafaf 3fe57d69348ceca0
  3feced7af43cc773 3fdb5d1009e15cc0 bfdb5d1009e15cc0 3feced7af43cc773 3fd58f9a75ab1fdd 3fee212104f686e5 bfee212104f686e5 3fd58f9a75ab1fdd
  3fef0a7efb9230d7 3fcf19f97b215f1b bfcf19f97b215f1b 3fef0a7efb9230d7 3fe073879922ffee 3feb728345196e3e bfeb728345196e3e 3fe073879922ffee
  3fe9b3e047f38741 3fe30ff7fce17035 bfe30ff7fce17035 3fe9b3e047f38741 3fc2c8106e8e613a 3fefa7557f08a517 bfefa7557f08a517 3fc2c8106e8e613a
  3fefa7557f08a517 3fc2c8106e8e613a bfc2c8106e8e613a 3fefa7557f08a517 3fe30ff7fce17035 3fe9b3e047f38741 bfe9b3e047f38741 3fe30ff7fce17035
  3feb728345196e3e 3fe073879922ffee bfe073879922ffee 3feb728345196e3e 3fcf19f97b215f1b 3fef0a7efb9230d7 bfef0a7efb9230d7 3fcf19f97b215f1b
  3fee212104f686e5 3fd58f9a75ab1fdd bfd58f9a75ab1fdd 3fee212104f686e5 3fdb5d1009e15cc0 3feced7af43cc773 bfeced7af43cc773 3fdb5d1009e15cc0
  3fe7b5df226aafaf 3fe57d69348ceca0 bfe57d69348ceca0 3fe7b5df226aafaf 3fa91f65f10dd814 3feff621e3796d7e bfeff621e3796d7e 3fa91f65f10dd814
  3feffd886084cd0d 3f992155f7a3667e bf992155f7a3667e 3feffd886084cd0d 3fe610b7551d2cdf 3fe72d0837efff96 bfe72d0837efff96 3fe610b7551d2cdf
  3fed4134d14dc93a 3fd9ef7943a8ed8a bfd9ef7943a8ed8a 3fed4134d14dc93a 3fd7088530fa459f 3feddb13b6ccc23c bfeddb13b6ccc23c 3fd7088530fa459f
  3fef38f3ac64e589 3fcc0b826a7e4f63 bfcc0b826a7e4f63 3fef38f3ac64e589 3fe11eb3541b4b23 3feb090a58150200 bfeb090a58150200 3fe11eb3541b4b23
  3fea29a7a0462782 3fe26d054cdd12df bfe26d054cdd12df 3fea29a7a0462782 3fc5e214448b3fc6 3fef8764fa714ba9 bfef8764fa714ba9 3fc5e214448b3fc6
  3fefc26470e19fd3 3fbf564e56a9730e bfbf564e56a9730e 3fefc26470e19fd3 3fe3affa292050b9 3fe93a22499263fb bfe93a22499263fb 3fe3affa292050b9
  3febd7c0ac6f952a 3fdf8ba4dbf89aba bfdf8ba4dbf89aba 3febd7c0ac6f952a 3fd111d262b1f677 3feed740e7684963 bfeed740e7684963 3fd111d262b1f677
  3fee6288ec48e112 3fd4135c94176601 bfd4135c94176601 3fee6288ec48e112 3fdcc66e9931c45e 3fec954b213411f5 bfec954b213411f5 3fdcc66e9931c45e
  3fe83b0e0bff976e 3fe4e6cabbe3e5e9 bfe4e6cabbe3e5e9 3fe83b0e0bff976e 3fb2d52092ce19f6 3fefe9cdad01883a bfefe9cdad01883a 3fb2d52092ce19f6
  3fefe9cdad01883a 3fb2d52092ce19f6 bfb2d52092ce19f6 3fefe9cdad01883a 3fe4e6cabbe3e5e9 3fe83b0e0bff976e bfe83b0e0bff976e 3fe4e6cabbe3e5e9
  3fec954b213411f5 3fdcc66e9931c45e bfdcc66e9931c45e 3fec954b213411f5 3fd4135c94176601 3fee6288ec48e112 bfee6288ec48e112 3fd4135c94176601
  3feed740e7684963 3fd111d262b1f677 bfd111d262b1f677 3feed740e7684963 3fdf8ba4dbf89aba 3febd7c0ac6f952a bfebd7c0ac6f952a 3fdf8ba4dbf89aba
  3fe93a22499263fb 3fe3affa292050b9 bfe3affa292050b9 3fe93a22499263fb 3fbf564e56a9730e 3fefc26470e19fd3 bfefc26470e19fd3 3fbf564e56a9730e
  3fef8764fa714ba9 3fc5e214448b3fc6 bfc5e214448b3fc6 3fef8764fa714ba9 3fe26d054cdd12df 3fea29a7a0462782 bfea29a7a0462782 3fe26d054cdd12df
  3feb090a58150200 3fe11eb3541b4b23 bfe11eb3541b4b23 3feb090a58150200 3fcc0b826a7e4f63 3fef38f3ac64e589 bfef38f3ac64e589 3fcc0b826a7e4f63
  3feddb13b6ccc23c 3fd7088530fa459f bfd7088530fa459f 3feddb13b6ccc23c 3fd9ef7943a8ed8a 3fed4134d14dc93a bfed4134d14dc93a 3fd9ef7943a8ed8a
  3fe72d0837efff96 3fe610b7551d2cdf bfe610b7551d2cdf 3fe72d0837efff96 3f992155f7a3667e 3feffd886084cd0d bfeffd886084cd0d 3f992155f7a3667e
  3fefff62169b92db 3f8921d1fcdec784 bf8921d1fcdec784 3fefff62169b92db 3fe6591925f0783d 3fe6e74454eaa8af bfe6e74454eaa8af 3fe6591925f0783d
  3fed696173c9e68b 3fd9372a63bc93d7 bfd9372a63bc93d7 3fed696173c9e68b 3fd7c3a9311dcce7 3fedb6526238a09b bfedb6526238a09b 3fd7c3a9311dcce7
  3fef4e603b0b2f2d 3fca82a025b00451 bfca82a025b00451 3fef4e603b0b2f2d 3fe1734d63dedb49 3fead2bc9e21d511 bfead2bc9e21d511 3fe1734d63dedb49
  3fea63091b02fae2 3fe21a799933eb59 bfe21a799933eb59 3fea63091b02fae2 3fc76dd9de50bf31 3fef7599a3a12077 bfef7599a3a12077 3fc76dd9de50bf31
  3fefce15fd6da67b 3fbc3785c79ec2d5 bfbc3785c79ec2d5 3fefce15fd6da67b 3fe3fed9534556d4 3fe8fbcca3ef940d bfe8fbcca3ef940d 3fe3fed9534556d4
  3fec08c426725549 3fdedc1952ef78d6 bfdedc1952ef78d6 3fec08c426725549 3fd1d3443f4cdb3e 3feebbd8c8df0b74 bfeebbd8c8df0b74 3fd1d3443f4cdb3e
  3fee817bab4cd10d 3fd35410c2e18152 bfd35410c2e18152 3fee817bab4cd10d 3fdd79775b86e389 3fec678b3488739b bfec678b3488739b 3fdd79775b86e389
  3fe87c400fba2ebf 3fe49a449b9b0939 bfe49a449b9b0939 3fe87c400fba2ebf 3fb5f6d00a9aa419 3fefe1cafcbd5b09 bfefe1cafcbd5b09 3fb5f6d00a9aa419
  3feff095658e71ad 3faf656e79f820e0 bfaf656e79f820e0 3feff095658e71ad 3fe5328292a35596 3fe7f8ece3571771 bfe7f8ece3571771 3fe5328292a35596
  3fecc1f0f3fcfc5c 3fdc1249d8011ee7 bfdc1249d8011ee7 3fecc1f0f3fcfc5c 3fd4d1e24278e76a 3fee426a4b2bc17e bfee426a4b2bc17e 3fd4d1e24278e76a
  3feef178a3e473c2 3fd04fb80e37fdae bfd04fb80e37fdae 3feef178a3e473c2 3fe01cfc874c3eb7 3feba5aa673590d2 bfeba5aa673590d2 3fe01cfc874c3eb7
  3fe9777ef4c7d742 3fe36058b10659f3 bfe36058b10659f3 3fe9777ef4c7d742 3fc139f0cedaf577 3fefb5797195d741 bfefb5797195d741 3fc139f0cedaf577
  3fef97f924c9099b 3fc45576b1293e5a bfc45576b1293e5a 3fef97f924c9099b 3fe2bedb25faf3ea 3fe9ef43ef29af94 bfe9ef43ef29af94 3fe2bedb25faf3ea
  3feb3e4d3ef55712 3fe0c9704d5d898f bfe0c9704d5d898f 3feb3e4d3ef55712 3fcd934fe5454311 3fef2252f7763ada bfef2252f7763ada 3fcd934fe5454311
  3fedfeae622dbe2b 3fd64c7ddd3f27c6 bfd64c7ddd3f27c6 3fedfeae622dbe2b 3fdaa6c82b6d3fca 3fed17e7743e35dc bfed17e7743e35dc 3fdaa6c82b6d3fca
  3fe771e75f037261 3fe5c77bbe65018c bfe5c77bbe65018c 3fe771e75f037261 3fa2d865759455cd 3feffa72effef75d bfeffa72effef75d 3fa2d865759455cd
  3feffa72effef75d 3fa2d865759455cd bfa2d865759455cd 3feffa72effef75d 3fe5c77bbe65018c 3fe771e75f037261 bfe771e75f037261 3fe5c77bbe65018c
  3fed17e7743e35dc 3fdaa6c82b6d3fca bfdaa6c82b6d3fca 3fed17e7743e35dc 3fd64c7ddd3f27c6 3fedfeae622dbe2b bfedfeae622dbe2b 3fd64c7ddd3f27c6
  3fef2252f7763ada 3fcd934fe5454311 bfcd934fe5454311 3fef2252f7763ada 3fe0c9704d5d898f 3feb3e4d3ef55712 bfeb3e4d3ef55712 3fe0c9704d5d898f
  3fe9ef43ef29af94 3fe2bedb25faf3ea bfe2bedb25faf3ea 3fe9ef43ef29af94 3fc45576b1293e5a 3fef97f924c9099b bfef97f924c9099b 3fc45576b1293e5a
  3fefb5797195d741 3fc139f0cedaf577 bfc139f0cedaf577 3fefb5797195d741 3fe36058b10659f3 3fe9777ef4c7d742 bfe9777ef4c7d742 3fe36058b10659f3
  3feba5aa673590d2 3fe01cfc874c3eb7 bfe01cfc874c3eb7 3feba5aa673590d2 3fd04fb80e37fdae 3feef178a3e473c2 bfeef178a3e473c2 3fd04fb80e37fdae
  3fee426a4b2bc17e 3fd4d1e24278e76a bfd4d1e24278e76a 3fee426a4b2bc17e 3fdc1249d8011ee7 3fecc1f0f3fcfc5c bfecc1f0f3fcfc5c 3fdc1249d8011ee7
  3fe7f8ece3571771 3fe5328292a35596 bfe5328292a35596 3fe7f8ece3571771 3faf656e79f820e0 3feff095658e71ad bfeff095658e71ad 3faf656e79f820e0
  3fefe1cafcbd5b09 3fb5f6d00a9aa419 bfb5f6d00a9aa419 3fefe1cafcbd5b09 3fe49a449b9b0939 3fe87c400fba2ebf bfe87c400fba2ebf 3fe49a449b9b0939
  3fec678b3488739b 3fdd79775b86e389 bfdd79775b86e389 3fec678b3488739b 3fd35410c2e18152 3fee817bab4cd10d bfee817bab4cd10d 3fd35410c2e18152
  3feebbd8c8df0b74 3fd1d3443f4cdb3e bfd1d3443f4cdb3e 3feebbd8c8df0b74 3fdedc1952ef78d6 3fec08c426725549 bfec08c426725549 3fdedc1952ef78d6
  3fe8fbcca3ef940d 3fe3fed9534556d4 bfe3fed9534556d4 3fe8fbcca3ef940d 3fbc3785c79ec2d5 3fefce15fd6da67b bfefce15fd6da67b 3fbc3785c79ec2d5
  3fef7599a3a12077 3fc76dd9de50bf31 bfc76dd9de50bf31 3fef7599a3a12077 3fe21a799933eb59 3fea63091b02fae2 bfea63091b02fae2 3fe21a799933eb59
  3fead2bc9e21d511 3fe1734d63dedb49 bfe1734d63dedb49 3fead2bc9e21d511 3fca82a025b00451 3fef4e603b0b2f2d bfef4e603b0b2f2d 3fca82a025b00451
  3fedb6526238a09b 3fd7c3a9311dcce7 bfd7c3a9311dcce7 3fedb6526238a09b 3fd9372a63bc93d7 3fed696173c9e68b bfed696173c9e68b 3fd9372a63bc93d7
  3fe6e74454eaa8af 3fe6591925f0783d bfe6591925f0783d 3fe6e74454eaa8af 3f8921d1fcdec784 3fefff62169b92db bfefff62169b92db 3f8921d1fcdec784
  3fefffd8858e8a92 3f7921f0fe670071 bf7921f0fe670071 3fefffd8858e8a92 3fe67cf78491af10 3fe6c40d73c18275 bfe6c40d73c18275 3fe67cf78491af10
  3fed7d0b02b8ecf9 3fd8daa52ec8a4b0 bfd8daa52ec8a4b0 3fed7d0b02b8ecf9 3fd820e3b04eaac4 3feda383a9668988 bfeda383a9668988 3fd820e3b04eaac4
  3fef58a2b1789e84 3fc9bdcbf2dc4366 bfc9bdcbf2dc4366 3fef58a2b1789e84 3fe19d5a09f2b9b8 3feab7325916c0d4 bfeab7325916c0d4 3fe19d5a09f2b9b8
  3fea7f58529fe69d 3fe1f0f08bbc861b bfe1f0f08bbc861b 3fea7f58529fe69d 3fc83366e89c64c6 3fef6c3f7df5bbb7 bfef6c3f7df5bbb7 3fc83366e89c64c6
  3fefd37914220b84 3fbaa7b724495c03 bfbaa7b724495c03 3fefd37914220b84 3fe425ff178e6bb1 3fe8dc45331698cc bfe8dc45331698cc 3fe425ff178e6bb1
  3fec20de3fa971b0 3fde83e0eaf85114 bfde83e0eaf85114 3fec20de3fa971b0 3fd233bbabc3bb71 3feeadb2e8e7a88e bfeeadb2e8e7a88e 3fd233bbabc3bb71
  3fee9084361df7f2 3fd2f422daec0387 bfd2f422daec0387 3fee9084361df7f2 3fddd28f1481cc58 3fec5042012b6907 bfec5042012b6907 3fddd28f1481cc58
  3fe89c7e9a4dd4aa 3fe473b51b987347 bfe473b51b987347 3fe89c7e9a4dd4aa 3fb787586a5d5b21 3fefdd539ff1f456 bfefdd539ff1f456 3fb787586a5d5b21
  3feff3830f8d575c 3fac428d12c0d7e3 bfac428d12c0d7e3 3feff3830f8d575c 3fe5581038975137 3fe7d7836cc33db2 bfe7d7836cc33db2 3fe5581038975137
  3fecd7d9898b32f6 3fdbb7cf2304bd01 bfdbb7cf2304bd01 3fecd7d9898b32f6 3fd530d880af3c24 3fee31eae870ce25 bfee31eae870ce25 3fd530d880af3c24
  3feefe220c0b95ec 3fcfdcdc1adfedf9 bfcfdcdc1adfedf9 3feefe220c0b95ec 3fe0485626ae221a 3feb8c38d27504e9 bfeb8c38d27504e9 3fe0485626ae221a
  3fe995cf2ed80d22 3fe338400d0c8e57 bfe338400d0c8e57 3fe995cf2ed80d22 3fc20116d4ec7bcf 3fefae8e8e46cfbb bfefae8e8e46cfbb 3fc20116d4ec7bcf
  3fef9fce55adb2c8 3fc38edbb0cd8d14 bfc38edbb0cd8d14 3fef9fce55adb2c8 3fe2e780e3e8ea17 3fe9d1b1f5ea80d5 bfe9d1b1f5ea80d5 3fe2e780e3e8ea17
  3feb5889fe921405 3fe09e907417c5e1 bfe09e907417c5e1 3feb5889fe921405 3fce56ca1e101a1b 3fef168f53f7205d bfef168f53f7205d 3fce56ca1e101a1b
  3fee100cca2980ac 3fd5ee27379ea693 bfd5ee27379ea693 3fee100cca2980ac 3fdb020d6c7f4009 3fed02d4feb2bd92 bfed02d4feb2bd92 3fdb020d6c7f4009
  3fe79400574f55e5 3fe5a28d2a5d7250 bfe5a28d2a5d7250 3fe79400574f55e5 3fa5fc00d290cd43 3feff871dadb81df bfeff871dadb81df 3fa5fc00d290cd43
  3feffc251df1d3f8 3f9f693731d1cf01 bf9f693731d1cf01 3feffc251df1d3f8 3fe5ec3495837074 3fe74f948da8d28d bfe74f948da8d28d 3fe5ec3495837074
  3fed2cb220e0ef9f 3fda4b4127dea1e5 bfda4b4127dea1e5 3fed2cb220e0ef9f 3fd6aa9d7dc77e17 3feded05f7de47da bfeded05f7de47da 3fd6aa9d7dc77e17
  3fef2dc9c9089a9d 3fcccf8cb312b286 bfcccf8cb312b286 3fef2dc9c9089a9d 3fe0f426bb2a8e7e 3feb23cd470013b4 bfeb23cd470013b4 3fe0f426bb2a8e7e
  3fea0c95eabaf937 3fe2960727629ca8 bfe2960727629ca8 3fea0c95eabaf937 3fc51bdf8597c5f2 3fef8fd5ffae41db bfef8fd5ffae41db 3fc51bdf8597c5f2
  3fefbc1617e44186 3fc072a047ba831d bfc072a047ba831d 3fefbc1617e44186 3fe3884185dfeb22 3fe958efe48e6dd7 bfe958efe48e6dd7 3fe3884185dfeb22
  3febbed7c49380ea 3fdfe2f64be71210 bfdfe2f64be71210 3febbed7c49380ea 3fd0b0d9cfdbdb90 3feee482e25a9dbc bfeee482e25a9dbc 3fd0b0d9cfdbdb90
  3fee529f04729ffc 3fd472b8a5571054 bfd472b8a5571054 3fee529f04729ffc 3fdc6c7f4997000b 3fecabc169a0b900 bfecabc169a0b900 3fdc6c7f4997000b
  3fe81a1b33b57acc 3fe50cc09f59a09b bfe50cc09f59a09b 3fe81a1b33b57acc 3fb1440134d709b3 3fefed58ecb673c4 bfefed58ecb673c4 3fb1440134d709b3
  3fefe5f3af2e3940 3fb4661179272096 bfb4661179272096 3fefe5f3af2e3940 3fe4c0a145ec0004 3fe85bc51ae958cc bfe85bc51ae958cc 3fe4c0a145ec0004
  3fec7e8e52233cf3 3fdd2016e8e9db5b bfdd2016e8e9db5b 3fec7e8e52233cf3 3fd3b3cefa0414b7 3fee7227db6a9744 bfee7227db6a9744 3fd3b3cefa0414b7
  3feec9b2d3c3bf84 3fd172a0d7765177 bfd172a0d7765177 3feec9b2d3c3bf84 3fdf3405963fd067 3febf064e15377dd bfebf064e15377dd 3fdf3405963fd067
  3fe91b166fd49da2 3fe3d78238c58344 bfe3d78238c58344 3fe91b166fd49da2 3fbdc70ecbae9fc9 3fefc8646cfeb721 bfefc8646cfeb721 3fbdc70ecbae9fc9
  3fef7ea629e63d6e 3fc6a81304f64ab2 bfc6a81304f64ab2 3fef7ea629e63d6e 3fe243d5fb98ac1f 3fea4678c8119ac8 bfea4678c8119ac8 3fe243d5fb98ac1f
  3feaee04b43c1474 3fe14915af336ceb bfe14915af336ceb 3feaee04b43c1474 3fcb4732ef3d6722 3fef43d085ff92dd bfef43d085ff92dd 3fcb4732ef3d6722
  3fedc8d7cb410260 3fd766340f2418f6 bfd766340f2418f6 3fedc8d7cb410260 3fd993716141bdff 3fed556f52e93eb1 bfed556f52e93eb1 3fd993716141bdff
  3fe70a42b3176d7a 3fe63503a31c1be9 bfe63503a31c1be9 3fe70a42b3176d7a 3f92d936bbe30efd 3feffe9cb44b51a1 bfeffe9cb44b51a1 3f92d936bbe30efd
  3feffe9cb44b51a1 3f92d936bbe30efd bf92d936bbe30efd 3feffe9cb44b51a1 3fe63503a31c1be9 3fe70a42b3176d7a bfe70a42b3176d7a 3fe63503a31c1be9
  3fed556f52e93eb1 3fd993716141bdff bfd993716141bdff 3fed556f52e93eb1 3fd766340f2418f6 3fedc8d7cb410260 bfedc8d7cb410260 3fd766340f2418f6
  3fef43d085ff92dd 3fcb4732ef3d6722 bfcb4732ef3d6722 3fef43d085ff92dd 3fe14915af336ceb 3feaee04b43c1474 bfeaee04b43c1474 3fe14915af336ceb
  3fea4678c8119ac8 3fe243d5fb98ac1f bfe243d5fb98ac1f 3fea4678c8119ac8 3fc6a81304f64ab2 3fef7ea629e63d6e bfef7ea629e63d6e 3fc6a81304f64ab2
  3fefc8646cfeb721 3fbdc70ecbae9fc9 bfbdc70ecbae9fc9 3fefc8646cfeb721 3fe3d78238c58344 3fe91b166fd49da2 bfe91b166fd49da2 3fe3d78238c58344
  3febf064e15377dd 3fdf3405963fd067 bfdf3405963fd067 3febf064e15377dd 3fd172a0d7765177 3feec9b2d3c3bf84 bfeec9b2d3c3bf84 3fd172a0d7765177
  3fee7227db6a9744 3fd3b3cefa0414b7 bfd3b3cefa0414b7 3fee7227db6a9744 3fdd2016e8e9db5b 3fec7e8e52233cf3 bfec7e8e52233cf3 3fdd2016e8e9db5b
  3fe85bc51ae958cc 3fe4c0a145ec0004 bfe4c0a145ec0004 3fe85bc51ae958cc 3fb4661179272096 3fefe5f3af2e3940 bfefe5f3af2e3940 3fb4661179272096
  3fefed58ecb673c4 3fb1440134d709b3 bfb1440134d709b3 3fefed58ecb673c4 3fe50cc09f59a09b 3fe81a1b33b57acc bfe81a1b33b57acc 3fe50cc09f59a09b
  3fecabc169a0b900 3fdc6c7f4997000b bfdc6c7f4997000b 3fecabc169a0b900 3fd472b8a5571054 3fee529f04729ffc bfee529f04729ffc 3fd472b8a5571054
  3feee482e25a9dbc 3fd0b0d9cfdbdb90 bfd0b0d9cfdbdb90 3feee482e25a9dbc 3fdfe2f64be71210 3febbed7c49380ea bfebbed7c49380ea 3fdfe2f64be71210
  3fe958efe48e6dd7 3fe3884185dfeb22 bfe3884185dfeb22 3fe958efe48e6dd7 3fc072a047ba831d 3fefbc1617e44186 bfefbc1617e44186 3fc072a047ba831d
  3fef8fd5ffae41db 3fc51bdf8597c5f2 bfc51bdf8597c5f2 3fef8fd5ffae41db 3fe2960727629ca8 3fea0c95eabaf937 bfea0c95eabaf937 3fe2960727629ca8
  3feb23cd470013b4 3fe0f426bb2a8e7e bfe0f426bb2a8e7e 3feb23cd470013b4 3fcccf8cb312b286 3fef2dc9c9089a9d bfef2dc9c9089a9d 3fcccf8cb312b286
  3feded05f7de47da 3fd6aa9d7dc77e17 bfd6aa9d7dc77e17 3feded05f7de47da 3fda4b4127dea1e5 3fed2cb220e0ef9f bfed2cb220e0ef9f 3fda4b4127dea1e5
  3fe74f948da8d28d 3fe5ec3495837074 bfe5ec3495837074 3fe74f948da8d28d 3f9f693731d1cf01 3feffc251df1d3f8 bfeffc251df1d3f8 3f9f693731d1cf01
  3feff871dadb81df 3fa5fc00d290cd43 bfa5fc00d290cd43 3feff871dadb81df 3fe5a28d2a5d7250 3fe79400574f55e5 bfe79400574f55e5 3fe5a28d2a5d7250
  3fed02d4feb2bd92 3fdb020d6c7f4009 bfdb020d6c7f4009 3fed02d4feb2bd92 3fd5ee27379ea693 3fee100cca2980ac bfee100cca2980ac 3fd5ee27379ea693
  3fef168f53f7205d 3fce56ca1e101a1b bfce56ca1e101a1b 3fef168f53f7205d 3fe09e907417c5e1 3feb5889fe921405 bfeb5889fe921405 3fe09e907417c5e1
  3fe9d1b1f5ea80d5 3fe2e780e3e8ea17 bfe2e780e3e8ea17 3fe9d1b1f5ea80d5 3fc38edbb0cd8d14 3fef9fce55adb2c8 bfef9fce55adb2c8 3fc38edbb0cd8d14
  3fefae8e8e46cfbb 3fc20116d4ec7bcf bfc20116d4ec7bcf 3fefae8e8e46cfbb 3fe338400d0c8e57 3fe995cf2ed80d22 bfe995cf2ed80d22 3fe338400d0c8e57
  3feb8c38d27504e9 3fe0485626ae221a bfe0485626ae221a 3feb8c38d27504e9 3fcfdcdc1adfedf9 3feefe220c0b95ec bfeefe220c0b95ec 3fcfdcdc1adfedf9
  3fee31eae870ce25 3fd530d880af3c24 bfd530d880af3c24 3fee31eae870ce25 3fdbb7cf2304bd01 3fecd7d9898b32f6 bfecd7d9898b32f6 3fdbb7cf2304bd01
  3fe7d7836cc33db2 3fe5581038975137 bfe5581038975137 3fe7d7836cc33db2 3fac428d12c0d7e3 3feff3830f8d575c bfeff3830f8d575c 3fac428d12c0d7e3
  3fefdd539ff1f456 3fb787586a5d5b21 bfb787586a5d5b21 3fefdd539ff1f456 3fe473b51b987347 3fe89c7e9a4dd4aa bfe89c7e9a4dd4aa 3fe473b51b987347
  3fec5042012b6907 3fddd28f1481cc58 bfddd28f1481cc58 3fec5042012b6907 3fd2f422daec0387 3fee9084361df7f2 bfee9084361df7f2 3fd2f422daec0387
  3feeadb2e8e7a88e 3fd233bbabc3bb71 bfd233bbabc3bb71 3feeadb2e8e7a88e 3fde83e0eaf85114 3fec20de3fa971b0 bfec20de3fa971b0 3fde83e0eaf85114
  3fe8dc45331698cc 3fe425ff178e6bb1 bfe425ff178e6bb1 3fe8dc45331698cc 3fbaa7b724495c03 3fefd37914220b84 bfefd37914220b84 3fbaa7b724495c03
  3fef6c3f7df5bbb7 3fc83366e89c64c6 bfc83366e89c64c6 3fef6c3f7df5bbb7 3fe1f0f08bbc861b 3fea7f58529fe69d bfea7f58529fe69d 3fe1f0f08bbc861b
  3feab7325916c0d4 3fe19d5a09f2b9b8 bfe19d5a09f2b9b8 3feab7325916c0d4 3fc9bdcbf2dc4366 3fef58a2b1789e84 bfef58a2b1789e84 3fc9bdcbf2dc4366
  3feda383a9668988 3fd820e3b04eaac4 bfd820e3b04eaac4 3feda383a9668988 3fd8daa52ec8a4b0 3fed7d0b02b8ecf9 bfed7d0b02b8ecf9 3fd8daa52ec8a4b0
  3fe6c40d73c18275 3fe67cf78491af10 bfe67cf78491af10 3fe6c40d73c18275 3f7921f0fe670071 3fefffd8858e8a92 bfefffd8858e8a92 3f7921f0fe670071
`);

// The FFT in the reference's layout: real parts in f[0, n/2), imaginary parts in f[n/2, n).
function fft(f, logn) {
  const n = 1 << logn, hn = n >> 1;
  for (let u = 1, m = 2, t = hn; u < logn; u++, m <<= 1) {
    const ht = t >> 1, hm = m >> 1;
    for (let i1 = 0, j1 = 0; i1 < hm; i1++, j1 += t) {
      const sRe = GM[(m + i1) << 1], sIm = GM[((m + i1) << 1) + 1];
      for (let j = j1; j < j1 + ht; j++) {
        const xRe = f[j], xIm = f[j + hn], yRe0 = f[j + ht], yIm0 = f[j + ht + hn];
        const yRe = yRe0 * sRe - yIm0 * sIm, yIm = yRe0 * sIm + yIm0 * sRe;
        f[j] = xRe + yRe;
        f[j + hn] = xIm + yIm;
        f[j + ht] = xRe - yRe;
        f[j + ht + hn] = xIm - yIm;
      }
    }
    t = ht;
  }
}

function ifft(f, logn) {
  const n = 1 << logn, hn = n >> 1;
  for (let u = logn, t = 1, m = n; u > 1; u--) {
    const hm = m >> 1, dt = t << 1;
    for (let i1 = 0, j1 = 0; j1 < hn; i1++, j1 += dt) {
      const sRe = GM[(hm + i1) << 1], sIm = -GM[((hm + i1) << 1) + 1];
      for (let j = j1; j < j1 + t; j++) {
        const xRe = f[j], xIm = f[j + hn], yRe = f[j + t], yIm = f[j + t + hn];
        f[j] = xRe + yRe;
        f[j + hn] = xIm + yIm;
        const dRe = xRe - yRe, dIm = xIm - yIm;
        f[j + t] = dRe * sRe - dIm * sIm;
        f[j + t + hn] = dRe * sIm + dIm * sRe;
      }
    }
    t = dt;
    m = hm;
  }
  if (logn > 0) {
    const ni = FPR_P2[logn];
    for (let u = 0; u < n; u++) f[u] *= ni;
  }
}

function polyAdd(a, b) {
  for (let u = 0; u < a.length; u++) a[u] += b[u];
}

function polySub(a, b) {
  for (let u = 0; u < a.length; u++) a[u] -= b[u];
}

function polyAdjFft(a) {
  for (let u = a.length >> 1; u < a.length; u++) a[u] = -a[u];
}

function polyMulFft(a, b) {
  const hn = a.length >> 1;
  for (let u = 0; u < hn; u++) {
    const aRe = a[u], aIm = a[u + hn], bRe = b[u], bIm = b[u + hn];
    a[u] = aRe * bRe - aIm * bIm;
    a[u + hn] = aRe * bIm + aIm * bRe;
  }
}

function polyMulconst(a, x) {
  for (let u = 0; u < a.length; u++) a[u] *= x;
}

// 1/(|a|² + |b|²) at each of the n/2 points.
function polyInvnorm2Fft(a, b) {
  const hn = a.length >> 1, d = new Float64Array(hn);
  for (let u = 0; u < hn; u++) {
    const aRe = a[u], aIm = a[u + hn], bRe = b[u], bIm = b[u + hn];
    d[u] = FPR_ONE / ((aRe * aRe + aIm * aIm) + (bRe * bRe + bIm * bIm));
  }
  return d;
}

// F·adj(f) + G·adj(g).
function polyAddMuladjFft(F, G, f, g) {
  const n = F.length, hn = n >> 1, d = new Float64Array(n);
  for (let u = 0; u < hn; u++) {
    const FRe = F[u], FIm = F[u + hn], GRe = G[u], GIm = G[u + hn];
    const fRe = f[u], fIm = -f[u + hn], gRe = g[u], gIm = -g[u + hn];
    const aRe = FRe * fRe - FIm * fIm, aIm = FRe * fIm + FIm * fRe;
    const bRe = GRe * gRe - GIm * gIm, bIm = GRe * gIm + GIm * gRe;
    d[u] = aRe + bRe;
    d[u + hn] = aIm + bIm;
  }
  return d;
}

// a·b for b self-adjoint (b holds only its n/2 real values).
function polyMulAutoadjFft(a, b) {
  const hn = a.length >> 1;
  for (let u = 0; u < hn; u++) {
    a[u] *= b[u];
    a[u + hn] *= b[u];
  }
}

function polyDivAutoadjFft(a, b) {
  const hn = a.length >> 1;
  for (let u = 0; u < hn; u++) {
    const ib = FPR_ONE / b[u];
    a[u] *= ib;
    a[u + hn] *= ib;
  }
}

// fpr_rint: round to nearest, ties to even, for |x| < 2^63 (the callers bound x).
const TWO52 = 4503599627370496;
function rint(x) {
  if (x >= 0) return x < TWO52 ? x + TWO52 - TWO52 : x;
  return x > -TWO52 ? x - TWO52 + TWO52 : x;
}

// The low 32 bits of fpr_rint(x), as the reference's casts to (u)int32_t keep them, for any finite
// x; beyond 2^63 fpr_rint's own (wrapped) arithmetic is reproduced.
function rintLow32(x) {
  if (Math.abs(x) < 9223372036854775808) {
    const r = rint(x) % 4294967296; // exact: r is an integer
    return r < 0 ? r + 4294967296 : r + 0;
  }
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, x);
  const bits = view.getBigUint64(0);
  let m = ((bits << 10n) | (1n << 62n)) & ((1n << 63n) - 1n);
  let e = 1085 - Number((bits >> 52n) & 0x7ffn);
  if (e >= 64) m = 0n;
  e &= 63;
  const d = (m << BigInt(63 - e)) & ((1n << 64n) - 1n);
  const sticky = (d & ((1n << 61n) - 1n)) !== 0n ? 1 : 0;
  m = (m >> BigInt(e)) + BigInt((0xc8 >> (Number(d >> 61n) | sticky)) & 1);
  return Number(BigInt.asUintN(32, bits >> 63n ? -m : m));
}

// ---------------------------------------------------------------------------------------------
// Exact integer polynomial arithmetic in Z[x]/(x^n + 1) over BigInt coefficients.
// ---------------------------------------------------------------------------------------------

// The reference's small primes (keygen.c PRIMES, the first 157: as many as logn = 9 uses).
const PRIMES = `
  2147473409 2147389441 2147387393 2147377153 2147358721 2147352577 2147346433 2147338241 2147309569 2147297281
  2147295233 2147239937 2147235841 2147217409 2147205121 2147196929 2147178497 2147100673 2147082241 2147074049
  2147051521 2147043329 2147039233 2146988033 2146963457 2146959361 2146938881 2146908161 2146885633 2146871297
  2146846721 2146834433 2146818049 2146775041 2146756609 2146744321 2146738177 2146736129 2146713601 2146695169
  2146656257 2146650113 2146646017 2146643969 2146603009 2146572289 2146547713 2146508801 2146492417 2146490369
  2146459649 2146447361 2146441217 2146437121 2146430977 2146418689 2146406401 2146404353 2146379777 2146363393
  2146355201 2146336769 2146312193 2146293761 2146283521 2146203649 2146154497 2146142209 2146127873 2146099201
  2146093057 2146091009 2146078721 2146060289 2146048001 2146041857 2146019329 2145986561 2145976321 2145964033
  2145906689 2145875969 2145871873 2145841153 2145832961 2145816577 2145785857 2145755137 2145742849 2145728513
  2145699841 2145691649 2145687553 2145673217 2145630209 2145595393 2145587201 2145525761 2145495041 2145466369
  2145445889 2145390593 2145372161 2145361921 2145359873 2145355777 2145343489 2145325057 2145318913 2145312769
  2145300481 2145282049 2145232897 2145218561 2145187841 2145181697 2145175553 2145079297 2145021953 2145015809
  2145003521 2144960513 2144944129 2144935937 2144894977 2144888833 2144880641 2144864257 2144827393 2144806913
  2144796673 2144778241 2144759809 2144757761 2144729089 2144727041 2144696321 2144667649 2144573441 2144555009
  2144550913 2144536577 2144524289 2144512001 2144468993 2144458753 2144421889 2144409601 2144370689 2144348161
  2144335873 2144329729 2144327681 2144309249 2144296961 2144290817 2144243713
`;
let primeProducts = null;
// The product of the first k primes: the modulus of a CRT rebuild over k words.
function primeProduct(k) {
  if (!primeProducts) {
    primeProducts = [1n];
    for (const p of PRIMES.trim().split(/\s+/)) primeProducts.push(primeProducts[primeProducts.length - 1] * BigInt(p));
  }
  return primeProducts[k];
}

// zint_rebuild_CRT(..., normalize_signed = 1) over k primes: each value modulo their product, in
// [-(P-1)/2, (P-1)/2].
function smodPoly(a, k) {
  const P = primeProduct(k), half = P >> 1n;
  return a.map((x) => {
    if (x <= half && x >= -half) return x;
    x %= P;
    if (x < 0n) x += P;
    return x > half ? x - P : x;
  });
}

function maxBits(a) {
  let max = 0n;
  for (const x of a) if (x > max || -x > max) max = x < 0n ? -x : x;
  return max === 0n ? 0 : max.toString(16).length * 4; // an upper bound
}

// out ± a·b mod x^n + 1, in doubles: exact while every partial sum stays below 2^53.
function convInto(out, a, b, sign) {
  const n = a.length;
  for (let i = 0; i < n; i++) {
    const ai = sign * a[i];
    if (ai === 0) continue;
    for (let j = 0; j < n - i; j++) out[i + j] += ai * b[j];
    for (let j = n - i; j < n; j++) out[i + j - n] -= ai * b[j];
  }
}

const LIMB = 21, LIMB_MASK = (1n << 21n) - 1n;

// Signed 21-bit limbs: a[i] = Σ_j limbs[j][i]·2^(21j), |limbs[j][i]| < 2^21.
function toLimbs(a, count) {
  const limbs = Array.from({ length: count }, () => new Float64Array(a.length));
  a.forEach((x, i) => {
    const neg = x < 0n;
    if (neg) x = -x;
    for (let j = 0; x !== 0n; j++, x >>= 21n) {
      const w = Number(x & LIMB_MASK);
      limbs[j][i] = neg ? -w : w;
    }
  });
  return limbs;
}

// The exact product a·b mod x^n + 1 (arrays of BigInt): in doubles when every sum stays below 2^53,
// else by 21-bit limbs in doubles when there are few, else in BigInt.
function mulNega(a, b) {
  const n = a.length, lg = Math.log2(n), ba = maxBits(a), bb = maxBits(b);
  if (ba === 0 || bb === 0) return new Array(n).fill(0n);
  if (ba + bb + lg <= 53) {
    const out = new Float64Array(n);
    convInto(out, Float64Array.from(a, Number), Float64Array.from(b, Number), 1);
    return Array.from(out, BigInt);
  }
  const la = Math.ceil(ba / LIMB), lb = Math.ceil(bb / LIMB);
  if (la * lb <= n && Math.min(la, lb) * n <= 2048) {
    // Each limb product is below 2^42, so the at most min(la, lb) convolutions of one limb weight
    // sum below 2^53; the weights are then joined in BigInt, most significant first.
    const A = toLimbs(a, la), B = toLimbs(b, lb), out = new Array(n).fill(0n), acc = new Float64Array(n);
    for (let s = la + lb - 2; s >= 0; s--) {
      acc.fill(0);
      for (let j = Math.max(0, s - lb + 1); j <= Math.min(s, la - 1); j++) convInto(acc, A[j], B[s - j], 1);
      for (let i = 0; i < n; i++) out[i] = (out[i] << 21n) + BigInt(acc[i]);
    }
    return out;
  }
  const out = new Array(n).fill(0n);
  for (let i = 0; i < n; i++) {
    const ai = a[i];
    if (ai === 0n) continue;
    for (let j = 0; j < n - i; j++) out[i + j] += ai * b[j];
    for (let j = n - i; j < n; j++) out[i + j - n] -= ai * b[j];
  }
  return out;
}

// The field norm N(f), of degree n/2: N(f)(x²) = f(x)·f(−x) = f0(x²)² − x²·f1(x²)².
function fieldNorm(f) {
  const hn = f.length >> 1, f0 = [], f1 = [];
  for (let i = 0; i < hn; i++) {
    f0.push(f[2 * i]);
    f1.push(f[2 * i + 1]);
  }
  const a = mulNega(f0, f0), b = mulNega(f1, f1);
  return a.map((x, i) => (i === 0 ? x + b[hn - 1] : x - b[i - 1]));
}

// F'(x²)·g(−x): the unreduced F of a level from the F' of the level below.
function lift(Fd, g) {
  const n = g.length, spread = new Array(n).fill(0n);
  Fd.forEach((x, i) => (spread[2 * i] = x));
  return mulNega(spread, g.map((x, i) => (i & 1 ? -x : x)));
}

// poly_big_to_fp on a value of `len` 31-bit words: its absolute value's words, least significant
// first, each scaled by 2^(31·j) and added in turn.
function bigToFp(x, len) {
  const neg = x < 0n;
  if (neg) x = -x;
  let r = 0, scale = FPR_ONE;
  for (let j = 0; j < len; j++, x >>= 31n, scale *= FPR_PTWO31) {
    const w = Number(x & 0x7fffffffn);
    r += (neg ? -w : w) * scale;
  }
  return r;
}

// The top `len` words of each coefficient (all but its lowest `shift` bits), as doubles.
const bigToFpPoly = (a, shift, len) => {
  const s = BigInt(shift);
  return Float64Array.from(a, (x) => bigToFp(x >> s, len));
};

// ---------------------------------------------------------------------------------------------
// solve_NTRU (keygen.c) at logn = 9: the deepest level by the extended GCD of the resultants, the
// intermediate depths 8..2, then depths 1 and 0.
// ---------------------------------------------------------------------------------------------

const MAX_BL_SMALL = [1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209];
const MAX_BL_LARGE = [2, 2, 5, 7, 12, 21, 40, 78, 157, 308];
const BITLENGTH = [[4, 0], [11, 1], [24, 1], [50, 1], [102, 1], [202, 2], [401, 4], [794, 5],
  [1577, 8], [3138, 13], [6308, 25]];
const DEPTH_INT_FG = 4;
const P0 = 2147473409; // PRIMES[0].p

// zint_bezout: u, v with x·u − y·v = 1, 0 <= u <= y, 0 <= v <= x (unique), for odd coprime x, y.
function bezout(x, y) {
  if (!(x & y & 1n)) return null;
  let r0 = x, r1 = y, s0 = 1n, s1 = 0n;
  while (r1 !== 0n) {
    const t = r0 / r1;
    [r0, r1, s0, s1] = [r1, r0 - t * r1, s1, s0 - t * s1];
  }
  if (r0 !== 1n) return null;
  let u = s0 % y;
  if (u < 0n) u += y;
  if (y === 1n) u = 1n;
  return { u, v: (x * u - 1n) / y };
}

// solve_NTRU_intermediate: from F', G' of depth + 1 (MAX_BL_SMALL[depth + 1] words), the reduced
// F, G of this depth (MAX_BL_SMALL[depth] words); f, g are this depth's.
function solveIntermediate(depth, Fd, Gd, f, g) {
  const logn = LOGN - depth, n = 1 << logn;
  const slen = MAX_BL_SMALL[depth], llen = MAX_BL_LARGE[depth];
  const Ft = smodPoly(lift(Fd, g), llen), Gt = smodPoly(lift(Gd, f), llen);

  let rlen = Math.min(slen, 10);
  const scaleFg = 31 * (slen - rlen);
  const rt3 = bigToFpPoly(f, scaleFg, rlen), rt4 = bigToFpPoly(g, scaleFg, rlen);
  const minblFg = BITLENGTH[depth][0] - 6 * BITLENGTH[depth][1];
  const maxblFg = BITLENGTH[depth][0] + 6 * BITLENGTH[depth][1];
  fft(rt3, logn);
  fft(rt4, logn);
  const rt5 = polyInvnorm2Fft(rt3, rt4);
  polyAdjFft(rt3);
  polyAdjFft(rt4);

  let FGlen = llen, maxblFG = 31 * llen, scaleK = maxblFG - minblFg;
  const k = new Array(n);
  for (;;) {
    rlen = Math.min(FGlen, 10);
    const scaleFG = 31 * (FGlen - rlen);
    const rt1 = bigToFpPoly(Ft, scaleFG, rlen), rt2 = bigToFpPoly(Gt, scaleFG, rlen);
    fft(rt1, logn);
    fft(rt2, logn);
    polyMulFft(rt1, rt3);
    polyMulFft(rt2, rt4);
    polyAdd(rt2, rt1);
    polyMulAutoadjFft(rt2, rt5);
    ifft(rt2, logn);

    let dc = scaleK - scaleFG + scaleFg, pt;
    if (dc < 0) {
      dc = -dc;
      pt = FPR_TWO;
    } else {
      pt = FPR_ONEHALF;
    }
    let pdc = FPR_ONE;
    while (dc !== 0) {
      if (dc & 1) pdc *= pt;
      dc >>= 1;
      pt *= pt;
    }
    for (let u = 0; u < n; u++) {
      const xv = rt2[u] * pdc;
      if (!(FPR_MTWO31M1 < xv) || !(xv < FPR_PTWO31M1)) return null;
      k[u] = BigInt(rint(xv));
    }

    // (F, G) −= k·(f, g)·2^scale_k, in FGlen words; at low depth k·f goes through the RNS of
    // slen + 1 primes (poly_sub_scaled_ntt).
    let kf = mulNega(k, f), kg = mulNega(k, g);
    if (depth <= DEPTH_INT_FG) {
      kf = smodPoly(kf, slen + 1);
      kg = smodPoly(kg, slen + 1);
    }
    const bits = 31 * FGlen, shift = BigInt(scaleK);
    for (let u = 0; u < n; u++) {
      Ft[u] = BigInt.asIntN(bits, Ft[u] - (kf[u] << shift));
      Gt[u] = BigInt.asIntN(bits, Gt[u] - (kg[u] << shift));
    }

    const newMaxblFG = scaleK + maxblFg + 10;
    if (newMaxblFG < maxblFG) {
      maxblFG = newMaxblFG;
      if (FGlen * 31 >= maxblFG + 31) {
        FGlen--;
        for (let u = 0; u < n; u++) {
          Ft[u] = BigInt.asIntN(31 * FGlen, Ft[u]);
          Gt[u] = BigInt.asIntN(31 * FGlen, Gt[u]);
        }
      }
    }
    if (scaleK <= 0) break;
    scaleK = Math.max(scaleK - 25, 0);
  }
  return [Ft.map((x) => BigInt.asIntN(31 * slen, x)), Gt.map((x) => BigInt.asIntN(31 * slen, x))];
}

// zint_one_to_plain on the 32-bit word (uint32_t)fpr_rint(x): bit 30 is the sign.
const onePlain = (w) => (w | ((w & 0x40000000) << 1)) | 0;

// solve_NTRU_binary_depth1: one Babai reduction in floating point; F, G come back as the
// one-word values depth 0 reads.
function solveDepth1(Fd, Gd, f, g) {
  const logn = LOGN - 1, slen = MAX_BL_SMALL[1], llen = MAX_BL_LARGE[1];
  const Ft = smodPoly(lift(Fd, g), llen), Gt = smodPoly(lift(Gd, f), llen);
  const rt1 = bigToFpPoly(Ft, 0, llen), rt2 = bigToFpPoly(Gt, 0, llen);
  const rt3 = bigToFpPoly(f, 0, slen), rt4 = bigToFpPoly(g, 0, slen);
  fft(rt1, logn);
  fft(rt2, logn);
  fft(rt3, logn);
  fft(rt4, logn);
  const rt5 = polyAddMuladjFft(rt1, rt2, rt3, rt4);
  const rt6 = polyInvnorm2Fft(rt3, rt4);
  polyMulAutoadjFft(rt5, rt6);
  ifft(rt5, logn);
  for (let u = 0; u < rt5.length; u++) {
    const z = rt5[u];
    if (!(z < FPR_PTWO63M1) || !(FPR_MTWO63M1 < z)) return null;
    rt5[u] = rint(z);
  }
  fft(rt5, logn);
  polyMulFft(rt3, rt5);
  polyMulFft(rt4, rt5);
  polySub(rt1, rt3);
  polySub(rt2, rt4);
  ifft(rt1, logn);
  ifft(rt2, logn);
  return [Int32Array.from(rt1, (x) => onePlain(rintLow32(x))), Int32Array.from(rt2, (x) => onePlain(rintLow32(x)))];
}

// Symmetric residues modulo p0, in place: the reference's modp_norm.
function normP0(a) {
  for (let i = 0; i < a.length; i++) {
    let x = a[i] % P0;
    if (x < 0) x += P0;
    a[i] = x > (P0 - 1) / 2 ? x - P0 : x;
  }
  return a;
}

// solve_NTRU_binary_depth0: everything modulo p0, but for the Babai quotient (FFT). Every
// product here stays below 2^53, so doubles hold it exactly. The reference takes the depth-1 F, G
// and the quotient k (int32 values) modulo p0 with modp_set, which reduces x only for
// -p0 <= x < p0; within 2^14 of ±2^31 its NTT would not compute modulo p0 and this port does
// not follow it there. Those values are near 2^11 and 2^16, far from 2^31.
function solveDepth0(Fd, Gd, f, g) {
  const n = N, hn = n >> 1;
  const Fs = new Float64Array(n), Gs = new Float64Array(n);
  for (let i = 0; i < hn; i++) {
    Fs[2 * i] = Fd[i];
    Gs[2 * i] = Gd[i];
  }
  const fneg = Float64Array.from(f, (x, i) => (i & 1 ? -x : x)), gneg = Float64Array.from(g, (x, i) => (i & 1 ? -x : x));
  const fadj = Float64Array.from(f, (x, i) => (i === 0 ? x : -f[n - i])), gadj = Float64Array.from(g, (x, i) => (i === 0 ? x : -g[n - i]));
  const ff = Float64Array.from(f), gf = Float64Array.from(g);
  const Fu = new Float64Array(n), Gu = new Float64Array(n);
  convInto(Fu, Fs, gneg, 1);
  convInto(Gu, Gs, fneg, 1);
  normP0(Fu);
  normP0(Gu);
  const t1 = new Float64Array(n), t2 = new Float64Array(n);
  convInto(t1, Fu, fadj, 1);
  convInto(t1, Gu, gadj, 1);
  convInto(t2, ff, fadj, 1);
  convInto(t2, gf, gadj, 1);
  normP0(t1);
  normP0(t2);

  const rt3 = Float64Array.from(t2);
  fft(rt3, LOGN);
  const rt2 = rt3.slice(0, hn);
  const rt = Float64Array.from(t1);
  fft(rt, LOGN);
  polyDivAutoadjFft(rt, rt2);
  ifft(rt, LOGN);
  const k = Float64Array.from(rt, (x) => rintLow32(x) | 0);
  convInto(Fu, k, ff, -1);
  convInto(Gu, k, gf, -1);
  return [normP0(Fu), normP0(Gu)];
}

// F (and G) with fG − gF = q, coefficients in [-127, 127], or null: solve_NTRU.
function solveNTRU(f, g) {
  const fs = [Array.from(f, BigInt)], gs = [Array.from(g, BigInt)];
  for (let d = 1; d < LOGN; d++) {
    fs.push(smodPoly(fieldNorm(fs[d - 1]), MAX_BL_SMALL[d]));
    gs.push(smodPoly(fieldNorm(gs[d - 1]), MAX_BL_SMALL[d]));
  }

  // solve_NTRU_deepest: the resultants, rebuilt unsigned over MAX_BL_SMALL[9] primes.
  const len = MAX_BL_SMALL[LOGN], P = primeProduct(len);
  const umod = (x) => ((x % P) + P) % P;
  const bz = bezout(umod(fieldNorm(fs[LOGN - 1])[0]), umod(fieldNorm(gs[LOGN - 1])[0]));
  if (!bz) return null;
  const Fq = bz.v * BigInt(Q), Gq = bz.u * BigInt(Q), top = 1n << BigInt(31 * len);
  if (Fq >= top || Gq >= top) return null;
  let F = [BigInt.asIntN(31 * len, Fq)], G = [BigInt.asIntN(31 * len, Gq)];

  for (let depth = LOGN - 1; depth >= 2; depth--) {
    const r = solveIntermediate(depth, F, G, fs[depth], gs[depth]);
    if (!r) return null;
    [F, G] = r;
  }
  const r1 = solveDepth1(F, G, fs[1], gs[1]);
  if (!r1) return null;
  const [F0, G0] = solveDepth0(r1[0], r1[1], f, g);

  for (let u = 0; u < N; u++) if (Math.abs(F0[u]) > 127 || Math.abs(G0[u]) > 127) return null;
  const e = new Float64Array(N);
  convInto(e, Float64Array.from(f), G0, 1);
  convInto(e, Float64Array.from(g), F0, -1);
  for (let u = 0; u < N; u++) if (e[u] !== (u === 0 ? Q : 0)) return null;
  return Int8Array.from(F0);
}

// ---------------------------------------------------------------------------------------------
// h = g/f mod q (compute_public), with an NTT over Z_q: null when f is not invertible.
// ---------------------------------------------------------------------------------------------

const powq = (b, e) => {
  let r = 1;
  for (b %= Q; e > 0; e >>= 1, b = (b * b) % Q) if (e & 1) r = (r * b) % Q;
  return r;
};
const PSI = powq(11, (Q - 1) / (2 * N)); // a primitive 1024-th root of unity mod q

// a ↦ (a(ψ^(2k+1)))_k in bit-reversed order, or back.
function nttq(a, inverse) {
  const r = Int32Array.from(a, (x) => ((x % Q) + Q) % Q), psi = inverse ? powq(PSI, 2 * N - 1) : PSI;
  if (!inverse) for (let i = 0, w = 1; i < N; i++, w = (w * psi) % Q) r[i] = (r[i] * w) % Q;
  for (let i = 1, j = 0; i < N; i++) {
    let bit = N >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) [r[i], r[j]] = [r[j], r[i]];
  }
  for (let len = 2; len <= N; len <<= 1) {
    const step = powq(psi, (2 * N) / len);
    for (let i = 0; i < N; i += len) {
      for (let j = 0, w = 1; j < len >> 1; j++, w = (w * step) % Q) {
        const x = r[i + j], y = (r[i + j + (len >> 1)] * w) % Q;
        r[i + j] = (x + y) % Q;
        r[i + j + (len >> 1)] = (x - y + Q) % Q;
      }
    }
  }
  if (inverse) for (let i = 0, w = powq(N, Q - 2); i < N; i++, w = (w * psi) % Q) r[i] = (r[i] * w) % Q;
  return r;
}

function computePublic(f, g) {
  const F = nttq(f, false), G = nttq(g, false);
  for (let i = 0; i < N; i++) {
    if (F[i] === 0) return null;
    G[i] = (G[i] * powq(F[i], Q - 2)) % Q;
  }
  return nttq(G, true);
}

// ---------------------------------------------------------------------------------------------
// Zf(keygen) and nist.c's encodings.
// ---------------------------------------------------------------------------------------------

// The squared norm of the Gram-Schmidt row (q·adj(f), q·adj(g)) / (f·adj(f) + g·adj(g)) is below
// 1.17² q.
function orthogonalNormOk(f, g) {
  const rt1 = Float64Array.from(f), rt2 = Float64Array.from(g);
  fft(rt1, LOGN);
  fft(rt2, LOGN);
  const rt3 = polyInvnorm2Fft(rt1, rt2);
  polyAdjFft(rt1);
  polyAdjFft(rt2);
  polyMulconst(rt1, FPR_Q);
  polyMulconst(rt2, FPR_Q);
  polyMulAutoadjFft(rt1, rt3);
  polyMulAutoadjFft(rt2, rt3);
  ifft(rt1, LOGN);
  ifft(rt2, LOGN);
  let bnorm = 0;
  for (let u = 0; u < N; u++) {
    bnorm += rt1[u] * rt1[u];
    bnorm += rt2[u] * rt2[u];
  }
  return bnorm < FPR_BNORM_MAX;
}

// Values of `width` bits each, two's complement, most significant bit first.
function pack(out, at, values, width) {
  let acc = 0, accLen = 0;
  for (const v of values) {
    acc = ((acc << width) | (v & ((1 << width) - 1))) & 0xffffff;
    accLen += width;
    while (accLen >= 8) {
      accLen -= 8;
      out[at++] = acc >>> accLen;
    }
  }
  return at;
}

/**
 * The Falcon-512 key pair of a 48-byte seed, exactly as the round-3 reference implementation makes
 * it: { secretKey: Uint8Array(1281), publicKey: Uint8Array(897) }. Deterministic and synchronous.
 */
export function keygen(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== SEED_BYTES) {
    throw new TypeError(`keygen: the seed must be a Uint8Array of ${SEED_BYTES} bytes`);
  }
  const rng = new Shake256(seed), f = new Int8Array(N), g = new Int8Array(N);
  for (;;) {
    smallGauss(rng, f);
    smallGauss(rng, g);
    if (f.some((x) => x >= 32 || x <= -32) || g.some((x) => x >= 32 || x <= -32)) continue;
    let norm = 0;
    for (let u = 0; u < N; u++) norm += f[u] * f[u] + g[u] * g[u];
    if (norm >= 16823) continue;
    if (!orthogonalNormOk(f, g)) continue;
    const h = computePublic(f, g);
    if (!h) continue;
    const F = solveNTRU(f, g);
    if (!F) continue;

    const secretKey = new Uint8Array(SECRET_KEY_BYTES), publicKey = new Uint8Array(PUBLIC_KEY_BYTES);
    secretKey[0] = 0x50 + LOGN;
    pack(secretKey, pack(secretKey, pack(secretKey, 1, f, 6), g, 6), F, 8);
    publicKey[0] = LOGN;
    pack(publicKey, 1, h, 14);
    return { secretKey, publicKey };
  }
}
