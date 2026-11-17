// The wallet: BIP39 24-word mnemonics, an HKDF-SHA512 seed per account, and the Falcon-512 key pair of
// that seed made by the round-3 reference implementation's key generation (keygen.js), so that
// recovery (the same mnemonic, passphrase and index) gives the same keys and the same address.
//
//   mnemonic     32 random bytes (crypto.getRandomValues), BIP39: 8 checksum bits (SHA-256), 24 words
//   root seed    BIP39: PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic" ‖ NFKD(passphrase), 2048), 64 bytes
//   account seed HKDF-SHA512(root seed, salt empty, info = u8(26) ‖ WALLET_SCHEME ‖ u32_be(index)), 48 bytes
//   keys         keygen(account seed); address = address(public key)
//
// Only generated words are accepted: deriving refuses anything but 24 listed words with a valid
// checksum. One ES module, no dependencies: Node.js >= 20 and browsers (crypto.subtle needs a
// secure context there).

import { WORDLIST } from './bip39-english.js';
import { keygen } from './keygen.js';
import { address, formatAddress } from './falcon512.js';

export const WALLET_SCHEME = 'apogee/wallet/falcon512/v1';

const WORDS = 24, ENTROPY_BYTES = 32;
const WORD_INDEX = new Map(WORDLIST.map((word, i) => [word, i]));
const utf8 = (text) => new TextEncoder().encode(text);

// SHA-256 (FIPS 180-4), synchronous: the mnemonic checksum. Browsers offer only an async digest.
const K256 = Uint32Array.from(`428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
  d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 e49b69c1 efbe4786 0fc19dc6
  240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da 983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147
  06ca6351 14292967 27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 a2bfe8a1
  a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070 19a4c116 1e376c08 2748774c 34b0bcb5
  391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7
  c67178f2`.trim().split(/\s+/), (h) => parseInt(h, 16));
const rotr = (x, n) => (x >>> n) | (x << (32 - n));

function sha256(data) {
  const blocks = (data.length + 72) >> 6, buf = new Uint8Array(64 * blocks), view = new DataView(buf.buffer);
  buf.set(data);
  buf[data.length] = 0x80;
  view.setUint32(buf.length - 8, Math.floor(data.length / 0x20000000));
  view.setUint32(buf.length - 4, data.length * 8);
  const H = Uint32Array.of(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);
  const W = new Uint32Array(64);
  for (let at = 0; at < buf.length; at += 64) {
    for (let t = 0; t < 16; t++) W[t] = view.getUint32(at + 4 * t);
    for (let t = 16; t < 64; t++) {
      const a = W[t - 15], b = W[t - 2];
      W[t] = W[t - 16] + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + W[t - 7] + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10));
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[t] + W[t]) | 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      [h, g, f, e, d, c, b, a] = [g, f, e, (d + t1) | 0, c, b, a, (t1 + t2) | 0];
    }
    [a, b, c, d, e, f, g, h].forEach((x, i) => (H[i] += x));
  }
  const out = new Uint8Array(32);
  H.forEach((x, i) => new DataView(out.buffer).setUint32(4 * i, x));
  return out;
}

/** The 24 words of 32 bytes of entropy (exported for tests: a wallet only takes generated words). */
export function _entropyToMnemonic(entropy) {
  if (!(entropy instanceof Uint8Array) || entropy.length !== ENTROPY_BYTES) {
    throw new TypeError('wallet: the entropy is a Uint8Array of 32 bytes');
  }
  const bits = new Uint8Array(ENTROPY_BYTES + 1);
  bits.set(entropy);
  bits[ENTROPY_BYTES] = sha256(entropy)[0];
  const words = [];
  for (let i = 0; i < WORDS; i++) {
    let v = 0;
    for (let b = 11 * i; b < 11 * i + 11; b++) v = (v << 1) | ((bits[b >> 3] >> (7 - (b & 7))) & 1);
    words.push(WORDLIST[v]);
  }
  return words.join(' ');
}

/** A new mnemonic: 24 words for 32 bytes from crypto.getRandomValues. */
export function generateMnemonic() {
  return _entropyToMnemonic(globalThis.crypto.getRandomValues(new Uint8Array(ENTROPY_BYTES)));
}

/**
 * The canonical sentence of a mnemonic (NFKD, lower case, single spaces), or a thrown Error unless it
 * is 24 words of the BIP39 English list with a valid checksum.
 */
export function validateMnemonic(text) {
  if (typeof text !== 'string') throw new TypeError('wallet: a mnemonic is a string');
  const words = text.normalize('NFKD').toLowerCase().trim().split(/\s+/);
  if (words.length !== WORDS) throw new Error(`wallet: a mnemonic is 24 words, not ${words.length}`);
  const bits = new Uint8Array(ENTROPY_BYTES + 1);
  words.forEach((word, i) => {
    const v = WORD_INDEX.get(word);
    if (v === undefined) throw new Error(`wallet: word ${i + 1} of the mnemonic is not in the BIP39 English list`);
    for (let j = 0; j < 11; j++) {
      const b = 11 * i + j;
      if ((v >> (10 - j)) & 1) bits[b >> 3] |= 0x80 >> (b & 7);
    }
  });
  if (sha256(bits.subarray(0, ENTROPY_BYTES))[0] !== bits[ENTROPY_BYTES]) {
    throw new Error('wallet: the mnemonic\'s checksum does not match (a word is wrong or out of place)');
  }
  return words.join(' ');
}

/** BIP39's 64-byte seed: PBKDF2-HMAC-SHA512 of the mnemonic as given, no validation. */
export async function mnemonicToSeed(mnemonic, passphrase = '') {
  if (typeof mnemonic !== 'string' || typeof passphrase !== 'string') {
    throw new TypeError('wallet: the mnemonic and the passphrase are strings');
  }
  const key = await globalThis.crypto.subtle.importKey('raw', utf8(mnemonic.normalize('NFKD')), 'PBKDF2', false, ['deriveBits']);
  const salt = utf8('mnemonic' + passphrase.normalize('NFKD'));
  return new Uint8Array(await globalThis.crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-512', salt, iterations: 2048 }, key, 512));
}

/** Account `index`'s 48-byte key-generation seed (index an integer in [0, 2^32)). */
export async function accountSeed(rootSeed, index) {
  if (!(rootSeed instanceof Uint8Array) || rootSeed.length !== 64) throw new TypeError('wallet: a root seed is 64 bytes');
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) {
    throw new RangeError('wallet: an account index is an integer from 0 to 2^32 - 1');
  }
  const scheme = utf8(WALLET_SCHEME), info = new Uint8Array(1 + scheme.length + 4);
  info[0] = scheme.length;
  info.set(scheme, 1);
  new DataView(info.buffer).setUint32(1 + scheme.length, index);
  const key = await globalThis.crypto.subtle.importKey('raw', rootSeed, 'HKDF', false, ['deriveBits']);
  // RFC 5869's absent salt: HashLen zero bytes.
  const params = { name: 'HKDF', hash: 'SHA-512', salt: new Uint8Array(64), info };
  return new Uint8Array(await globalThis.crypto.subtle.deriveBits(params, key, 48 * 8));
}

/**
 * Account `index` of a mnemonic: { secretKey, publicKey, address (32 bytes), addressText }. Throws
 * unless the mnemonic is valid (validateMnemonic); case and spacing do not matter.
 */
export async function deriveAccount(mnemonic, { passphrase = '', index = 0 } = {}) {
  const root = await mnemonicToSeed(validateMnemonic(mnemonic), passphrase);
  const seed = await accountSeed(root, index);
  const { secretKey, publicKey } = keygen(seed);
  root.fill(0);
  seed.fill(0);
  const addr = address(publicKey);
  return { secretKey, publicKey, address: addr, addressText: formatAddress(addr) };
}
