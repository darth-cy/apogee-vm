// Falcon-512 with Poseidon2's HashToPoint: Falcon-512 v1.2 (the NIST round-3 specification) with one
// change, HashToPoint, which is a Poseidon2-A64-C5 sponge over (the key digest K, salt, context,
// message) instead of SHAKE256(salt || message). A key's address is K's first 32 bytes. The
// construction is specified in the apogee-vm repository's docs/spec/precompiles.md, "HashToPoint" in
// the section "The Falcon-512 lattice check". Signatures are NOT interoperable with standard Falcon-512.
//
// Isomorphic ES modules, no dependencies: Node.js >= 20 and browsers. Randomness comes from
// globalThis.crypto.getRandomValues. Signing uses floating point and is not constant time, so a
// secret key belongs on its owner's device.

import { keygen, SEED_BYTES } from './keygen.js';

export const PUBLIC_KEY_BYTES = 897, SECRET_KEY_BYTES = 1281, SIGNATURE_BYTES = 666, SALT_BYTES = 40;

const N = 512, Q = 12289;
const BOUND = 34034726; // ⌊β²⌋
const SIGMA = 165.7366171829776, SIGMA_MIN = 1.2778336969128337, SIGMA_MAX = 1.8205;
const PK_HEADER = 0x09, SK_HEADER = 0x59, SIG_HEADER = 0x39; // logn = 9; signature: compressed, padded
const S2_BYTES = SIGNATURE_BYTES - 1 - SALT_BYTES; // 625 bytes = 5,000 bits of compressed s2

function bytes(x, name) {
  if (!(x instanceof Uint8Array)) throw new TypeError(`falcon512: ${name} must be a Uint8Array`);
  return x;
}

// ---------------------------------------------------------------------------------------------
// Randomness: the platform CSPRNG, drawn 4 KiB at a time.
// ---------------------------------------------------------------------------------------------

let pool = new Uint8Array(0), poolAt = 0;
function randomByte() {
  if (poolAt === pool.length) {
    pool = new Uint8Array(4096);
    globalThis.crypto.getRandomValues(pool);
    poolAt = 0;
  }
  return pool[poolAt++];
}

// ---------------------------------------------------------------------------------------------
// Poseidon2-A64-C5 (apogee-vm crates/transcript): width 16, x^3, 6 full + 42 partial + 6 full
// rounds over p = 2^64 - 59. The constants are params.rs's, value for value and in order.
// ---------------------------------------------------------------------------------------------

const P = 0xFFFFFFFFFFFFFFC5n;
const lanes = (s) => s.trim().split(/\s+/).map((h) => BigInt('0x' + h));

// μ_i − 1, the internal matrix M_I = J + diag(μ − 1) less its all-ones part.
const DIAG = lanes(`
  8c10a8ce5034e7e8 1931fc0383e50211 28a06de917b5d352 de5501ea0f11990f
  913b96b19d26392d 8e47a0e65a05faf5 80d19f2bb9d0fbb9 c2ced79b54e7316a
  aa2a5e9d40524eb4 f604423d63ed4f6e c7e8f0e92efb8b44 9b329edf06deff59
  465217a0ebca4c1b 56311fe256fa128f 17a9d46b512d7804 30e56eedd3c99289`);
// The six initial full rounds' constants, 16 a round.
const RC_INITIAL = lanes(`
  7047c3dc92736be8 4493a8148a6f85ca aa60e3cde94e1752 9e868d333548f562
  afb5da41ea86af6c 3640076df46fa9aa 785a94c5ac04eb8d 0c6498cbd5e2756f
  2ab1c8083c056bf6 3025f57d43c7b82a 24c3d60fb40045ae c084235576b7920a
  d11b2f79642586b8 63a14204a158a1df e9e8e3fb5f2372d5 b5c744f0f8adf8ce
  8841ceb2663bf698 1a6200674f23a7f1 89b3f9918dce930b 39f476b0c95ac243
  22d4b17ba98cc6e7 74eb860a60fc142c 55dc3dd52a793c13 8a8048133ffd8a25
  789e9cf21d9e1715 40a637ab67b5aa9d fa7b127c1135e2e3 7046a3936101d50e
  07580b9720662d51 8c401a60da88834f 003016b03062520f 67142dabeba7687b
  4b5d16d072172d6c fd35431f2d69d48e 987a1441571589de 9134f9b4bd1594da
  7a9b6fb03c5c2962 3b291c38b7edd9b9 24931e69038b728d 339c23001c614132
  a98f4b79d34f265a 821127f3072b6cf3 214381bfd649e69b 750a7869b93d8984
  ce8ac028aa6d34c7 fdd95e5b3d86c657 db92c09767eea4d3 01f21817ebf66c2f
  7aca4f6765c1e105 4ebfcebc9634eeb5 23b3eef3d59f2166 e4c2dbdfc2e3e9e8
  258e3d922a4b03ee dff083155c0fc28b 28617062f92168ea 04f0e53af046c649
  8f8f74b0a4abae33 f0e2e98381e99875 eb4eff03a2682e29 a0055d24fba968cd
  b1cec5c313d84751 ef7655f4987cf404 cdd1bbc7391c086f dbec6998cd68a80f
  bfef9492a6e6192b 8c4141c123487ba5 a54f4abf6c6e0552 f710588192b9284e
  70bef2935d0acef8 53211acdd552a5f6 ef2fca1b25eab2dc 2081f0277d8167e0
  685a09e92794ed36 e29cc173d5373fac 2749d6757b198213 9d4d74709a367a2a
  c092b54fe1655479 4112c0c934c109cc a9ae7703d7ce37da 295180cb458087ee
  65c3ff6c9f07b89b 2dcefb7ae8af32ad 53b232e84dc95ab0 3b296bdca82908af
  22472c00e68d68b7 3a93373a4d71d610 4efe9f02230015c5 c142e21311370345
  3b25e29c5a5cf8c5 394a449627b021e7 05bc705ee1bedf16 4ae02b950fb9d7c6
  88df86d112f7a18f a7c4f5f0fd1d06e0 6e4119b73e2fedba 49fafc501c2cedc4`);
// The 42 partial rounds' constants, one a round, for lane 0.
const RC_PARTIAL = lanes(`
  cc437af88bbc0fa4 f0a621c4752bdcdf cd77843261a3d77d 1f0e8c1f92705922
  6d9d9f0da8042761 26d4b4ce501b92c8 0ce8adb236fbd227 bc29af81a0edcf83
  6c88dea317938d36 7aca51f495edffca 6671b2c701e764a6 843fa7a64dd4a931
  34e275bda3984a9d 4ca92812ad89f96a 1d453072915ce8b5 17eaf2f33ff4696e
  2ae093012dcfaf50 960799ac3f64a26d 9249961472410929 3efd5875220115d6
  4ad33e50fcf28800 2947729a976f4640 f7b8501bdd7fecae d2820fdb1125e1c4
  bee18d4f1faa1c5d 8a12dc23ebbb624d 9a88a574e9a5d1a1 d9618bfc06c34237
  5b8e74f87df39ebe 01726b7266ed0a1c d913a49f91add3db 6fe213c90004b238
  f369cd3786d834cf 81651049d3bbf44b 728fe04ac8bd27e7 760149424519aae3
  cc151807658ffbd7 ef5a05fd98da42f7 783abe8ec6bc1142 c00ac779ccd5ebab
  589ec82758720308 fd00cf0b5de1777f`);
// The six terminal full rounds' constants, 16 a round.
const RC_TERMINAL = lanes(`
  08d6ecaabd6f14e4 d12d4f88cc7da760 d4ef6925e221b290 c324c3c0ae15d53c
  c6f882c1f9fd30a4 31662cdab9b4e735 5f2067d276827b46 588cf7b2490a348e
  31b16cdf0d50c5eb 5c0243180fafd3b2 fa72734258fab521 65e297e796a54f51
  9a68ece0a22e26bc 8e7615315ac51c90 229acf1a7e925152 f64dd4532e540a39
  62ae031cf7a7d995 5e34b48d1e962bf7 a2b5b361403041ba 8288735c528d99e2
  d0ee5943d1b14363 2301d5fc0917b286 7e9f5a70d3249531 de85c17d19b453cd
  c1e0e752a6a689e3 2324dcfeebef4ff8 ee25cb5533b2c207 26da424af5e7ea36
  d1217659c2585c40 1bbcb9c8e4f7d654 1b937902864e3ae1 b8720228358cf562
  dac70675806d0815 272bd4dd369b391e 1fb7513d441421f9 16ef5200d3f55fd4
  bf3268bcaf09bc1f 317f01a7bd98bfbc 2fcca518b59f92b3 c6ef11fd798fdfd8
  222540acb83348e7 ea31ace636446ee3 d93ac783c2cc080f 64f1e2ba0c16303d
  71ea3b96ba39b249 2f0a03c8bad7aded e1e0b81894cefe02 f60f1d58edc555c7
  712dea3d3c682cf1 580016de651247c9 f393596a6ef02e68 ec115ff8a0ab2064
  380b5ea2b04a2a12 43b949b9011d6c75 699a25d56d047b11 3e092f396912fcb5
  165e9c674d76a458 5d15ce9a69c163ce 039bff63b9c5e2af 1cef1449c294fa1a
  496ac40c9d7d01ca bc1c27b72416ed8a 3291357bc2cf9454 5f19d250ad19803c
  745468970f131f9e 8ce512afd566b2a9 ffd028a7c48113e6 5359cb4a9e3c8443
  eb8cb2e7677f78d7 464e2b31a8aa27fe c53aa7ecfb2c3a96 20d5e4e411405082
  a3ca0a158aec73f4 a2190d708bbfa769 b02df32f934c6216 0f0d4731494230cc
  7975b2c2945426a2 8d32496b5308d589 0c5967274b5b80d7 cd5e81cb46aece9e
  80f933ac98dcb532 668ee364f565c43e fd0a78bba94d272f daff8e36ee05df53
  9859ba5cbcb486fa 3e71731fd4737391 2cae0f202c85aac6 941f5238f52a9690
  69cea53aab57c457 f6342424d0e21b8c eba4cf91ac60d6ab 4f0d0ab2616fcc22
  558c2a137c5467c1 51fe2d8ed6076c81 d0e2aee95b4673c5 b5b7c45223d8273d`);

const cube = (x) => x * x % P * x % P;

// The external layer circ(2·M4, M4, M4, M4): block b becomes M4·s_b + Σ_j M4·s_j, with HorizenLabs'
// M4 = [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]].
function external(s) {
  for (let b = 0; b < 16; b += 4) {
    const x0 = s[b], x1 = s[b + 1], x2 = s[b + 2], x3 = s[b + 3];
    s[b] = 5n * x0 + 7n * x1 + x2 + 3n * x3;
    s[b + 1] = 4n * x0 + 6n * x1 + x2 + x3;
    s[b + 2] = x0 + 3n * x1 + 5n * x2 + 7n * x3;
    s[b + 3] = x0 + x1 + 4n * x2 + 6n * x3;
  }
  for (let r = 0; r < 4; r++) {
    const sum = s[r] + s[r + 4] + s[r + 8] + s[r + 12];
    for (let i = r; i < 16; i += 4) s[i] = (s[i] + sum) % P;
  }
}

// A round constant into every lane, the S-box on every lane, then the external layer.
function fullRound(s, rc, at) {
  for (let i = 0; i < 16; i++) s[i] = cube((s[i] + rc[at + i]) % P);
  external(s);
}

// The permutation, in place on 16 canonical lanes (BigInt in [0, p)).
function permute(s) {
  external(s);
  for (let r = 0; r < 6; r++) fullRound(s, RC_INITIAL, 16 * r);
  for (const rc of RC_PARTIAL) {
    s[0] = cube((s[0] + rc) % P);
    let sum = 0n;
    for (const x of s) sum += x;
    for (let i = 0; i < 16; i++) s[i] = (DIAG[i] * s[i] + sum) % P; // M_I = J + diag(μ − 1)
  }
  for (let r = 0; r < 6; r++) fullRound(s, RC_TERMINAL, 16 * r);
}

/** Internal (tests): the permutation of 16 lanes, as a new array. */
export function _poseidon2(state) {
  const s = Array.from(state, (x) => BigInt(x) % P);
  if (s.length !== 16) throw new RangeError('falcon512: a Poseidon2 state is 16 lanes');
  permute(s);
  return s;
}

// ---------------------------------------------------------------------------------------------
// The sponge, the transcript's overwrite duplex (rate 8, capacity 8) from a zero state with lazy
// permutation and no padding, and what it serves: the key digest K, the address and its checksum,
// and HashToPoint.
// ---------------------------------------------------------------------------------------------

const ascii = (text) => Uint8Array.from(text, (ch) => ch.charCodeAt(0));
const KEY_DOMAIN = ascii('apogee/key/v1'), SCHEME_ID = ascii('falcon512-poseidon2/v1');
const CHECKSUM_DOMAIN = ascii('apogee/address-checksum/v1');
const SIGNATURE_DOMAIN = ascii('apogee/falcon512/hash-to-point/v1');
const MAX_CONTEXT_BYTES = 255; // FIPS 204's and 206's bound
const QN = BigInt(Q), T = P / QN ** 4n * QN ** 4n; // 808·q^4: lanes ≥ T are rejected

// The squeeze stream after absorbing `fields`, [tag, bytes] each: the tag, the length in bytes, then
// 7-byte little-endian chunks (the last may be shorter), each lane overwriting the next rate lane, the
// state permuted first when the rate is full; then a permutation and all eight rate lanes, again.
function* sponge(...fields) {
  const s = Array(16).fill(0n);
  let pos = 0;
  const absorb = (x) => {
    if (pos === 8) {
      permute(s);
      pos = 0;
    }
    s[pos++] = x;
  };
  for (const [tag, data] of fields) {
    absorb(BigInt(tag));
    absorb(BigInt(data.length));
    for (let i = 0; i < data.length; i += 7) {
      let lo = 0, hi = 0; // bytes i..i+4 and i+4..i+7: below 2^32 and 2^24, exact as Numbers
      for (let k = Math.min(i + 4, data.length) - 1; k >= i; k--) lo = lo * 256 + data[k];
      for (let k = Math.min(i + 7, data.length) - 1; k >= i + 4; k--) hi = hi * 256 + data[k];
      absorb(BigInt(hi) << 32n | BigInt(lo));
    }
  }
  for (;;) {
    permute(s);
    yield* s.slice(0, 8);
  }
}

// The first `count` lanes of a stream, each 8 bytes little-endian.
function laneBytes(lanes, count) {
  const out = new Uint8Array(8 * count), view = new DataView(out.buffer);
  for (let i = 0; i < count; i++) view.setBigUint64(8 * i, lanes.next().value, true);
  return out;
}

/** K, the 64-byte key digest of any byte string, normally an encoded public key. */
export function keyDigest(publicKey) {
  return laneBytes(sponge([1, KEY_DOMAIN], [2, SCHEME_ID], [3, bytes(publicKey, 'publicKey')]), 8);
}

/** The 32-byte address of a public key: K's first 32 bytes. */
export function address(publicKey) {
  return keyDigest(publicKey).slice(0, 32);
}

// The address's checksum: the first 4 bytes of the stream's first lane after (CHECKSUM_DOMAIN, address).
const checksum = (addr) => laneBytes(sponge([1, CHECKSUM_DOMAIN], [2, addr]), 1).subarray(0, 4);
const hex = (data) => Array.from(data, (b) => b.toString(16).padStart(2, '0')).join('');

/** The address's text: "0x", then the address and its 4-byte checksum in lowercase hex (74 characters). */
export function formatAddress(addr) {
  if (bytes(addr, 'address').length !== 32) throw new RangeError('falcon512: an address is 32 bytes');
  return '0x' + hex(addr) + hex(checksum(addr));
}

/** The 32-byte address a text gives: exactly "0x", then 72 hex digits of either case, the address and
 * its checksum. Throws for anything else. */
export function parseAddress(text) {
  if (typeof text === 'string' && /^0x[0-9a-fA-F]{72}$/.test(text)) {
    const addr = Uint8Array.from(text.slice(2, 66).match(/../g), (d) => parseInt(d, 16));
    if (hex(checksum(addr)) === text.slice(66).toLowerCase()) return addr;
  }
  throw new Error('falcon512: not an address ("0x", 64 hex digits and their 8-digit checksum)');
}

/** The point c in Z_q^512 for (encoded public key, 40-byte salt, message, context), K the key's digest. */
export function hashToPoint(publicKey, salt, message, context = new Uint8Array(0)) {
  const lanes = sponge([1, SIGNATURE_DOMAIN], [2, keyDigest(publicKey)], [3, bytes(salt, 'salt')],
    [4, bytes(context, 'context')], [5, bytes(message, 'message')]);
  const c = new Uint16Array(N);
  let i = 0;
  for (let x of lanes) {
    if (x >= T) continue;
    for (let j = 0; j < 4; j++, x /= QN) c[i++] = Number(x % QN); // least significant digit first
    if (i === N) return c;
  }
}

// ---------------------------------------------------------------------------------------------
// Z_q[x]/(x^512 + 1): the negacyclic NTT.
// ---------------------------------------------------------------------------------------------

const modq = (x) => ((x % Q) + Q) % Q;
const powq = (b, e) => {
  let r = 1;
  for (b = modq(b); e > 0; e >>= 1, b = b * b % Q) if (e & 1) r = r * b % Q;
  return r;
};
const PSI = powq(11, (Q - 1) / (2 * N)); // 11 generates Z_q^*, so ψ is a primitive 1024-th root of 1
const BITREV = new Uint16Array(N);
for (let i = 1; i < N; i++) BITREV[i] = (BITREV[i >> 1] >> 1) | ((i & 1) << 8);

// Forward: a ↦ (a(ψ^(2k+1)))_k, computed as the cyclic NTT of (a_i ψ^i) with ω = ψ². Inverse undoes it.
function ntt(a, inverse = false) {
  const psi = inverse ? powq(PSI, 2 * N - 1) : PSI, r = new Int32Array(N);
  for (let i = 0, w = 1; i < N; i++, w = w * psi % Q) r[BITREV[i]] = inverse ? modq(a[i]) : modq(a[i]) * w % Q;
  for (let len = 2; len <= N; len <<= 1) {
    const step = powq(psi, (2 * N) / len), half = len >> 1;
    for (let i = 0; i < N; i += len) {
      for (let j = 0, w = 1; j < half; j++, w = w * step % Q) {
        const u = r[i + j], v = r[i + j + half] * w % Q;
        r[i + j] = (u + v) % Q;
        r[i + j + half] = (u - v + Q) % Q;
      }
    }
  }
  if (inverse) for (let i = 0, w = powq(N, Q - 2); i < N; i++, w = w * psi % Q) r[i] = r[i] * w % Q;
  return r;
}

const mulq = (a, b) => {
  const A = ntt(a), B = ntt(b);
  return ntt(A.map((x, i) => x * B[i] % Q), true);
};

// ---------------------------------------------------------------------------------------------
// Encodings (v1.2 §3.11): bit strings are MSB first.
// ---------------------------------------------------------------------------------------------

function pack(values, width) {
  const out = new Uint8Array((values.length * width) / 8);
  for (let p = 0; p < values.length * width; p++) {
    if ((values[Math.floor(p / width)] >> (width - 1 - (p % width))) & 1) out[p >> 3] |= 0x80 >> (p & 7);
  }
  return out;
}

function unpack(data, count, width) {
  const out = new Int32Array(count);
  for (let p = 0; p < count * width; p++) {
    const i = Math.floor(p / width);
    out[i] = (out[i] << 1) | ((data[p >> 3] >> (7 - (p & 7))) & 1);
  }
  return out;
}

const encodePublicKey = (h) => Uint8Array.of(PK_HEADER, ...pack(h, 14));

// h, or null: exactly 897 bytes, the header, 512 coefficients of 14 bits each below q.
function decodePublicKey(pk) {
  if (!(pk instanceof Uint8Array) || pk.length !== PUBLIC_KEY_BYTES || pk[0] !== PK_HEADER) return null;
  const h = unpack(pk.subarray(1), N, 14);
  return h.every((x) => x < Q) ? h : null;
}

// Two's complement fields of `width` bits; −2^(width−1) is not an encoding.
function signedFields(data, width) {
  const half = 1 << (width - 1), out = unpack(data, N, width);
  if (out.includes(half)) return null;
  return out.map((x) => (x >= half ? x - 2 * half : x));
}

// Compress (Algorithm 17) into exactly 625 bytes, or null: per coefficient a sign bit, the low 7 bits
// of |s|, then |s| >> 7 zeros and a one. |s| > 2047 is refused, as Decompress refuses it.
function compress(s) {
  const out = new Uint8Array(S2_BYTES);
  let pos = 0;
  const put = (bit) => {
    if (bit) out[pos >> 3] |= 0x80 >> (pos & 7);
    pos++;
  };
  for (const x of s) {
    const a = Math.abs(x);
    if (a > 2047) return null;
    put(x < 0);
    for (let b = 6; b >= 0; b--) put((a >> b) & 1);
    for (let k = a >> 7; k > 0; k--) put(0);
    put(1);
    if (pos > 8 * S2_BYTES) return null;
  }
  return out;
}

// Decompress (Algorithm 18), strictly: no |s| > 2047, no −0, nothing past the 5,000 bits, and every
// bit after the 512th coefficient zero.
function decompress(data) {
  const nbits = 8 * data.length, s = new Int32Array(N);
  let pos = 0;
  const bit = () => (data[pos >> 3] >> (7 - (pos++ & 7))) & 1;
  for (let i = 0; i < N; i++) {
    if (pos + 9 > nbits) return null; // the sign, 7 low bits and at least the closing one
    const negative = bit();
    let a = 0;
    for (let b = 0; b < 7; b++) a = (a << 1) | bit();
    for (let k = 0; !bit(); ) {
      if (++k > 15 || pos >= nbits) return null;
      a += 128;
    }
    if (negative && a === 0) return null;
    s[i] = negative ? -a : a;
  }
  while (pos < nbits) if (bit()) return null;
  return s;
}

// s2, or null: exactly 666 bytes, the header, the salt, then compressed s2 and zero padding.
function decodeSignature(sig) {
  if (!(sig instanceof Uint8Array) || sig.length !== SIGNATURE_BYTES || sig[0] !== SIG_HEADER) return null;
  return decompress(sig.subarray(1 + SALT_BYTES));
}

// ---------------------------------------------------------------------------------------------
// Verify (Algorithm 16).
// ---------------------------------------------------------------------------------------------

// s1 = c − s2·h mod q, centered to [−6144, 6144]; accept iff ‖(s1, s2)‖² ≤ ⌊β²⌋.
function verifyCore(h, c, s2) {
  const t = mulq(s2, h);
  let norm = 0;
  for (let i = 0; i < N; i++) {
    let s1 = modq(c[i] - t[i]);
    if (s1 > Q >> 1) s1 -= Q;
    norm += s1 * s1 + s2[i] * s2[i];
  }
  return norm <= BOUND;
}

/** True iff `signature` is a valid signature of `message` under `publicKey` and `context` (at most
 * 255 bytes); never throws. K comes from the same bytes h is decoded from. */
export function verify(publicKey, message, signature, context = new Uint8Array(0)) {
  try {
    const h = decodePublicKey(publicKey), s2 = decodeSignature(signature);
    if (!h || !s2 || !(context.length <= MAX_CONTEXT_BYTES)) return false;
    const salt = signature.subarray(1, 1 + SALT_BYTES);
    return verifyCore(h, hashToPoint(publicKey, salt, message, context), s2);
  } catch {
    return false; // a message or context that is not a Uint8Array
  }
}

/** Internal (tests): verify with a given point c in place of HashToPoint. */
export function _verifyWithPoint(publicKey, c, signature) {
  try {
    const h = decodePublicKey(publicKey), s2 = decodeSignature(signature);
    return !!h && !!s2 && c.length === N && verifyCore(h, c, s2);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------
// The FFT over R[x]/(x^n + 1), n a power of two up to 512: n complex values (re, im interleaved in a
// Float64Array) at the roots of x^n + 1, ordered so that roots 2j and 2j + 1 are ±ζ_j with ζ_j² the
// j-th root for n/2. Then splitfft and mergefft (Algorithms 1–2) are one pass each, and since
// polynomials are real, FFT(f*) is the conjugate of FFT(f).
// ---------------------------------------------------------------------------------------------

// ODD[k]: the numerators a of the 2^k roots exp(iπa/2^k), in that order. ROOT[k]: ζ_j for n = 2^k.
const ODD = [[1]], ROOT = [null];
for (let k = 1; k <= 9; k++) {
  const n = 1 << k;
  ODD[k] = ODD[k - 1].flatMap((a) => [a, a + n]);
  ROOT[k] = Float64Array.from(ODD[k - 1].flatMap((a) => [Math.cos((Math.PI * a) / n), Math.sin((Math.PI * a) / n)]));
}

function split(F) {
  const n = F.length >> 1, z = ROOT[Math.log2(n)], A = new Float64Array(n), B = new Float64Array(n);
  for (let j = 0; j < n >> 1; j++) {
    const ar = F[4 * j], ai = F[4 * j + 1], br = F[4 * j + 2], bi = F[4 * j + 3], zr = z[2 * j], zi = z[2 * j + 1];
    A[2 * j] = (ar + br) / 2;
    A[2 * j + 1] = (ai + bi) / 2;
    const dr = (ar - br) / 2, di = (ai - bi) / 2; // times conj(ζ_j) = 1/ζ_j
    B[2 * j] = dr * zr + di * zi;
    B[2 * j + 1] = di * zr - dr * zi;
  }
  return [A, B];
}

function merge(A, B) {
  const n = A.length, z = ROOT[Math.log2(n)], F = new Float64Array(2 * n);
  for (let j = 0; j < n >> 1; j++) {
    const zr = z[2 * j], zi = z[2 * j + 1];
    const br = B[2 * j] * zr - B[2 * j + 1] * zi, bi = B[2 * j] * zi + B[2 * j + 1] * zr;
    F[4 * j] = A[2 * j] + br;
    F[4 * j + 1] = A[2 * j + 1] + bi;
    F[4 * j + 2] = A[2 * j] - br;
    F[4 * j + 3] = A[2 * j + 1] - bi;
  }
  return F;
}

// f ↦ FFT(f) for real coefficients; FFT of a constant (x + 1, the root −1) is the constant.
function fft(f) {
  if (f.length === 1) return Float64Array.of(Number(f[0]), 0);
  return merge(fft(f.filter((_, i) => !(i & 1))), fft(f.filter((_, i) => i & 1)));
}

function ifft(F) {
  if (F.length === 2) return [F[0]];
  const [A, B] = split(F), a = ifft(A), b = ifft(B);
  return a.flatMap((x, i) => [x, b[i]]);
}

const cadd = (a, b) => a.map((x, k) => x + b[k]);
const csub = (a, b) => a.map((x, k) => x - b[k]);
const cadj = (a) => a.map((x, k) => (k & 1 ? -x : x));
const cscale = (a, s) => a.map((x) => x * s);
function cmul(a, b) {
  const r = new Float64Array(a.length);
  for (let k = 0; k < a.length; k += 2) {
    r[k] = a[k] * b[k] - a[k + 1] * b[k + 1];
    r[k + 1] = a[k] * b[k + 1] + a[k + 1] * b[k];
  }
  return r;
}
function cdiv(a, b) {
  const r = new Float64Array(a.length);
  for (let k = 0; k < a.length; k += 2) {
    const d = b[k] * b[k] + b[k + 1] * b[k + 1];
    r[k] = (a[k] * b[k] + a[k + 1] * b[k + 1]) / d;
    r[k + 1] = (a[k + 1] * b[k] - a[k] * b[k + 1]) / d;
  }
  return r;
}

// ---------------------------------------------------------------------------------------------
// SamplerZ (Algorithms 12–15): the RCDT base sampler and BerExp/ApproxExp rejection.
// ---------------------------------------------------------------------------------------------

// RCDT (Table 3.1), each 72-bit threshold split into its high 24 and low 48 bits.
const RCDT = [
  3024686241123004913666n, 1564742784480091954050n, 636254429462080897535n, 199560484645026482916n,
  47667343854657281903n, 8595902006365044063n, 1163297957344668388n, 117656387352093658n,
  8867391802663976n, 496969357462633n, 20680885154299n, 638331848991n, 14602316184n, 247426747n,
  3104126n, 28824n, 198n, 1n,
].map((v) => [Number(v >> 48n), Number(v & 0xffffffffffffn)]);

// ApproxExp's C: 2^63 · f(−x) ≈ 2^63 · exp(−x) on [0, ln 2].
const C = [
  0x00000004741183A3n, 0x00000036548CFC06n, 0x0000024FDCBF140An, 0x0000171D939DE045n,
  0x0000D00CF58F6F84n, 0x000680681CF796E3n, 0x002D82D8305B0FEAn, 0x011111110E066FD0n,
  0x0555555555070F00n, 0x155555555581FF00n, 0x400000000002B400n, 0x7FFFFFFFFFFF4800n,
  0x8000000000000000n,
];

// z0 in {0, ..., 18}: u = UniformBits(72), big-endian from nine bytes (as Table 3.2's vectors read
// them), counted against RCDT.
function baseSampler() {
  let hi = 0, lo = 0;
  for (let k = 0; k < 3; k++) hi = hi * 256 + randomByte();
  for (let k = 0; k < 6; k++) lo = lo * 256 + randomByte();
  let z0 = 0;
  for (const [rh, rl] of RCDT) z0 += hi < rh || (hi === rh && lo < rl);
  return z0;
}

// ≈ 2^63 · ccs · exp(−x) for x in [0, ln 2] and ccs in [0, 1].
function approxExp(x, ccs) {
  let y = C[0];
  const z = BigInt(Math.floor(2 ** 63 * x));
  for (let i = 1; i < C.length; i++) y = C[i] - ((z * y) >> 63n);
  return (BigInt(Math.floor(2 ** 63 * ccs)) * y) >> 63n;
}

// One bit, 1 with probability ≈ ccs · exp(−x): compare 64-bit z ≈ 2^64 · ccs · exp(−x) bytewise
// against uniform bytes.
function berExp(x, ccs) {
  const s = Math.floor(x / Math.LN2), r = x - s * Math.LN2;
  const z = (2n * approxExp(r, ccs) - 1n) >> BigInt(Math.min(s, 63));
  for (let i = 56; ; i -= 8) {
    const w = randomByte() - Number((z >> BigInt(i)) & 0xffn);
    if (w !== 0 || i === 0) return w < 0;
  }
}

const INV_2SIGMA_MAX2 = 1 / (2 * SIGMA_MAX * SIGMA_MAX);

// z ~ D_{Z, μ, σ'} for σ' in [σ_min, σ_max].
function samplerZ(mu, sigma) {
  const s = Math.floor(mu), r = mu - s, dss = 1 / (2 * sigma * sigma), ccs = SIGMA_MIN / sigma;
  for (;;) {
    const z0 = baseSampler(), b = randomByte() & 1, z = b + (2 * b - 1) * z0;
    const x = (z - r) * (z - r) * dss - z0 * z0 * INV_2SIGMA_MAX2;
    if (berExp(x, ccs)) return z + s;
  }
}

// ---------------------------------------------------------------------------------------------
// The secret key: decoding, G, the basis B̂ and the normalized ffLDL tree (Algorithms 4, 8, 9).
// ---------------------------------------------------------------------------------------------

// γ = max(‖(g, −f)‖, ‖(q f*/(ff* + gg*), q g*/(ff* + gg*))‖) ≤ 1.17 √q (NTRUGen, (3.28)): a
// basis whose Gram–Schmidt norm keeps every leaf of the tree in [σ_min, σ_max].
function gammaOK(f, g, fh = fft(f), gh = fft(g)) {
  const bound = 1.17 * 1.17 * Q;
  if (f.reduce((a, x) => a + x * x, 0) + g.reduce((a, x) => a + x * x, 0) > bound) return false;
  let s = 0;
  for (let k = 0; k < fh.length; k += 2) s += 1 / (fh[k] ** 2 + fh[k + 1] ** 2 + gh[k] ** 2 + gh[k + 1] ** 2);
  return (Q * Q * s) / N <= bound;
}

// f, g, F, G, their FFTs, and h = g/f mod q from an encoded secret key; throws unless it is a
// Falcon-512 key: 1281 bytes, the header, no −2^(bits−1), f invertible mod q, fG − gF = q exactly,
// and γ in bound.
function decodeSecretKey(sk) {
  const malformed = () => new Error('falcon512: malformed secret key');
  if (!(sk instanceof Uint8Array) || sk.length !== SECRET_KEY_BYTES || sk[0] !== SK_HEADER) throw malformed();
  const f = signedFields(sk.subarray(1), 6), g = signedFields(sk.subarray(385), 6);
  const F = signedFields(sk.subarray(769), 8);
  if (!f || !g || !F) throw malformed();
  const fN = ntt(f);
  if (fN.includes(0)) throw malformed();
  const fInv = fN.map((x) => powq(x, Q - 2)), gN = ntt(g), FN = ntt(F);
  const h = ntt(gN.map((x, i) => x * fInv[i] % Q), true);
  const G = ntt(gN.map((x, i) => x * FN[i] % Q * fInv[i] % Q), true).map((x) => (x > Q >> 1 ? x - Q : x));
  const [fh, gh, Fh, Gh] = [f, g, F, G].map((a) => fft(a));
  // fG − gF over Z: |f|, |g| < 32, |F| < 128, |G| ≤ 6144 bound every coefficient below 2^27, so
  // the FFT's rounding error is far below 1/2 and rounding recovers it exactly.
  const ntru = ifft(csub(cmul(fh, Gh), cmul(gh, Fh)));
  if (!ntru.every((x, i) => Math.round(x) === (i ? 0 : Q)) || !gammaOK(f, g, fh, gh)) throw malformed();
  return { h, fh, gh, Fh, Gh };
}

// The Falcon tree of the Gram matrix [[g00, g01], [g01*, g11]], its leaves normalized to σ/√leaf.
function ffLDL(g00, g01, g11) {
  const l = cdiv(cadj(g01), g00); // L10 = G10/G00
  const d11 = csub(g11, cmul(cmul(l, cadj(l)), g00));
  if (g00.length === 4) return { l, c0: SIGMA / Math.sqrt(g00[0]), c1: SIGMA / Math.sqrt(d11[0]) };
  const [a0, a1] = split(g00), [b0, b1] = split(d11);
  return { l, c0: ffLDL(a0, a1, a0), c1: ffLDL(b0, b1, b0) };
}

// ffSampling (Algorithm 11): z close to t, with t, z in FFT form.
function ffSampling(t0, t1, tree) {
  if (t0.length === 2) {
    const z0 = samplerZ(t0[0], tree), z1 = samplerZ(t1[0], tree);
    return [Float64Array.of(z0, 0), Float64Array.of(z1, 0)];
  }
  const z1 = merge(...ffSampling(...split(t1), tree.c1));
  const t0b = cadd(t0, cmul(csub(t1, z1), tree.l));
  const z0 = merge(...ffSampling(...split(t0b), tree.c0));
  return [z0, z1];
}

// ---------------------------------------------------------------------------------------------
// Sign (Algorithm 10).
// ---------------------------------------------------------------------------------------------

/** A 666-byte padded signature of `message` under `context` (at most 255 bytes); throws on a malformed
 * secret key or a longer context. */
export function sign(secretKey, message, context = new Uint8Array(0)) {
  if (bytes(context, 'context').length > MAX_CONTEXT_BYTES) {
    throw new RangeError('falcon512: a context is at most 255 bytes');
  }
  const { h, fh, gh, Fh, Gh } = decodeSecretKey(secretKey); // B̂ = [[ĝ, −f̂], [Ĝ, −F̂]]
  bytes(message, 'message');
  const tree = ffLDL(
    cadd(cmul(gh, cadj(gh)), cmul(fh, cadj(fh))),
    cadd(cmul(gh, cadj(Gh)), cmul(fh, cadj(Fh))),
    cadd(cmul(Gh, cadj(Gh)), cmul(Fh, cadj(Fh))),
  );
  const salt = Uint8Array.from({ length: SALT_BYTES }, randomByte);
  const c = hashToPoint(encodePublicKey(h), salt, message, context), ch = fft(c);
  const t0 = cscale(cmul(ch, Fh), -1 / Q), t1 = cscale(cmul(ch, fh), 1 / Q); // (ĉ, 0)·B̂⁻¹
  for (;;) {
    const [z0, z1] = ffSampling(t0, t1, tree);
    // s = (c, 0) − z·B: s1 = c − (z0 g + z1 G), s2 = z0 f + z1 F, rounded from the FFT.
    const v = ifft(cadd(cmul(z0, gh), cmul(z1, Gh))).map(Math.round);
    const s2 = ifft(cadd(cmul(z0, fh), cmul(z1, Fh))).map(Math.round);
    let norm = 0;
    for (let i = 0; i < N; i++) norm += (c[i] - v[i]) ** 2 + s2[i] ** 2;
    if (norm > BOUND) continue;
    const s = compress(s2);
    if (!s) continue;
    const sig = new Uint8Array(SIGNATURE_BYTES);
    sig[0] = SIG_HEADER;
    sig.set(salt, 1);
    sig.set(s, 1 + SALT_BYTES);
    return sig;
  }
}

/** The 897-byte public key h = g/f mod q of a secret key; throws on a malformed secret key. */
export function publicKeyFromSecretKey(secretKey) {
  return encodePublicKey(decodeSecretKey(secretKey).h);
}

// ---------------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------------

/**
 * A fresh key pair, { secretKey: 1281 bytes, publicKey: 897 bytes }: the reference keygen (keygen.js)
 * of 48 random bytes. A wallet derives its keys from a mnemonic instead (wallet.js), so that the same
 * words recover them.
 */
export function generateKeyPair() {
  return keygen(globalThis.crypto.getRandomValues(new Uint8Array(SEED_BYTES)));
}
