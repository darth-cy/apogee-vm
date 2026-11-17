import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getRandomValues } from 'node:crypto';
import {
  PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SIGNATURE_BYTES, SALT_BYTES,
  generateKeyPair, sign, verify, hashToPoint, publicKeyDigest, publicKeyFromSecretKey,
  _verifyWithPoint, _poseidon2,
} from '../falcon512.js';

const Q = 12289, P = 2n ** 64n - 59n;
const random = (n) => getRandomValues(new Uint8Array(n));
const flip = (data, bit) => {
  const out = data.slice();
  out[bit >> 3] ^= 0x80 >> (bit & 7);
  return out;
};
const SALT_BIT = 8, S2_BIT = 8 * (1 + SALT_BYTES); // the first bit of the salt, of compressed s2

// The bit (from the start of compressed s2) just past its 512th coefficient: what follows is padding.
function s2End(sig) {
  const bit = (p) => (sig[1 + SALT_BYTES + (p >> 3)] >> (7 - (p & 7))) & 1;
  let p = 0;
  for (let i = 0; i < 512; i++) {
    p += 8;
    while (!bit(p)) p++;
    p++;
  }
  return p;
}

test('Poseidon2-A64-C5 at [0, 1, ..., 15] is the generator\'s answer', () => {
  // GENERATOR_KAT, apogee-vm crates/transcript/tests/permutation.rs.
  const kat = `59bb4dfebd9c36af 04ef6d6db08fe0c3 58712eed1ea7dab3 6fdcdfd2cac82706
    c28b6eb60e8cc108 2dceea61d9b39cdc 38a3f5e89590b70b 8eaf1d087cb5fd81
    461e234d53d95651 3b06fe7980170f39 3f92a9c75ed65822 652f6a10605b537d
    11f277067885fa72 744edcd6a289fcb0 de10fc99342e7e2b 189b9d1e6db72de6`;
  const expected = kat.trim().split(/\s+/).map((h) => BigInt('0x' + h));
  assert.deepEqual(_poseidon2(Array.from({ length: 16 }, (_, i) => BigInt(i))), expected);
});

test('round trip: generateKeyPair, sign, verify; tampering refuses', () => {
  const { secretKey, publicKey } = generateKeyPair();
  assert.equal(secretKey.length, SECRET_KEY_BYTES);
  assert.equal(publicKey.length, PUBLIC_KEY_BYTES);
  assert.deepEqual(publicKeyFromSecretKey(secretKey), publicKey);
  for (const len of [0, 64, 200]) {
    const msg = random(len), sig = sign(secretKey, msg);
    assert.equal(sig.length, SIGNATURE_BYTES);
    assert.equal(sig[0], 0x39);
    assert.ok(verify(publicKey, msg, sig));
    const tampered = len ? flip(msg, 8 * len - 1) : new Uint8Array(1);
    assert.ok(!verify(publicKey, tampered, sig), 'message');
    assert.ok(!verify(publicKey, msg, flip(sig, SALT_BIT + 7)), 'salt');
    assert.ok(!verify(publicKey, msg, flip(sig, S2_BIT + 20)), 's2');
    const end = s2End(sig);
    assert.ok(end < 5000);
    assert.ok(!verify(publicKey, msg, flip(sig, S2_BIT + end)), 'the padding bit after s2');
    assert.ok(!verify(publicKey, msg, flip(sig, 8 * SIGNATURE_BYTES - 1)), 'the last padding bit');
    for (const header of [0x29, 0x3a, 0x59]) {
      assert.ok(!verify(publicKey, msg, Uint8Array.of(header, ...sig.subarray(1))), 'header');
    }
    assert.ok(!verify(publicKey, msg, sig.subarray(0, SIGNATURE_BYTES - 1)), 'short');
    assert.ok(!verify(publicKey, msg, Uint8Array.of(...sig, 0)), 'long');
  }

  // Strict key decoding: h_i + q has the same residue but is not an encoding.
  const msg = random(64), sig = sign(secretKey, msg), salt = sig.subarray(1, 1 + SALT_BYTES);
  const c = hashToPoint(publicKey, salt, msg);
  assert.ok(_verifyWithPoint(publicKey, c, sig));
  const bitAt = (data, p) => (data[p >> 3] >> (7 - (p & 7))) & 1;
  const field = (i) => Array.from({ length: 14 }, (_, b) => bitAt(publicKey, 8 + 14 * i + b));
  const i = Array.from({ length: 512 }, (_, k) => k).find((k) => parseInt(field(k).join(''), 2) + Q < 2 ** 14);
  let wide = publicKey;
  const value = parseInt(field(i).join(''), 2) + Q;
  for (let b = 0; b < 14; b++) {
    const bit = 8 + 14 * i + b;
    if (bitAt(wide, bit) !== ((value >> (13 - b)) & 1)) wide = flip(wide, bit);
  }
  assert.ok(!_verifyWithPoint(wide, c, sig), 'a coefficient >= q');
  assert.ok(!verify(wide, msg, sig), 'a coefficient >= q');

  // Two signatures of one message differ (fresh salt and sampler randomness).
  assert.notDeepEqual(sign(secretKey, msg), sign(secretKey, msg));

  // Malformed input: verify returns false, sign throws.
  assert.equal(verify(undefined, msg, sig), false);
  assert.equal(verify(publicKey, 'not bytes', sig), false);
  assert.equal(verify(publicKey, msg, Uint8Array.of(0x39, ...new Uint8Array(SIGNATURE_BYTES - 1))), false);
  assert.throws(() => sign(secretKey.subarray(1), msg));
  assert.throws(() => sign(flip(secretKey, 8 + 3), msg)); // f changes: fG − gF = q no longer holds
});

test('hashToPoint: deterministic, 512 coefficients below q, every input bit matters', () => {
  const pk = random(PUBLIC_KEY_BYTES), salt = random(SALT_BYTES), msg = random(50);
  const c = hashToPoint(pk, salt, msg);
  assert.ok(c instanceof Uint16Array);
  assert.equal(c.length, 512);
  assert.ok(c.every((x) => x < Q));
  assert.deepEqual(hashToPoint(pk, salt, msg), c);
  // One random bit in every 7-byte lane of each input, and each input's first and last bits.
  const inputs = [pk, salt, msg];
  for (let k = 0; k < 3; k++) {
    const data = inputs[k], bits = [0, 8 * data.length - 1];
    for (let at = 0; at < data.length; at += 7) {
      bits.push(8 * at + Math.floor(Math.random() * 8 * Math.min(7, data.length - at)));
    }
    for (const bit of bits) {
      const args = inputs.slice();
      args[k] = flip(data, bit);
      assert.notDeepEqual(hashToPoint(...args), c, `input ${k}, bit ${bit}`);
    }
  }
});

test('publicKeyDigest: eight lanes below p, for any bytes', () => {
  const { publicKey } = generateKeyPair();
  for (const data of [publicKey, new Uint8Array(0), random(100)]) {
    const digest = publicKeyDigest(data);
    assert.equal(digest.length, 8);
    assert.ok(digest.every((x) => typeof x === 'bigint' && x >= 0n && x < P));
    assert.deepEqual(publicKeyDigest(data), digest);
  }
  assert.notDeepEqual(publicKeyDigest(flip(publicKey, 100)), publicKeyDigest(publicKey));
});
