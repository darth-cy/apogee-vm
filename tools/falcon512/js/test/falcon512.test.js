import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getRandomValues } from 'node:crypto';
import {
  PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SIGNATURE_BYTES, SALT_BYTES,
  generateKeyPair, sign, verify, hashToPoint, keyDigest, address, formatAddress, parseAddress,
  publicKeyFromSecretKey, _verifyWithPoint, _poseidon2,
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

test('round trip: generateKeyPair, sign, verify under a context; tampering refuses', () => {
  const { secretKey, publicKey } = generateKeyPair();
  assert.equal(secretKey.length, SECRET_KEY_BYTES);
  assert.equal(publicKey.length, PUBLIC_KEY_BYTES);
  assert.deepEqual(publicKeyFromSecretKey(secretKey), publicKey);
  for (const [len, ctx] of [[0, new Uint8Array(0)], [92, random(255)], [200, random(9)]]) {
    const msg = random(len), sig = sign(secretKey, msg, ctx);
    assert.equal(sig.length, SIGNATURE_BYTES);
    assert.equal(sig[0], 0x39);
    assert.ok(verify(publicKey, msg, sig, ctx));
    const tampered = len ? flip(msg, 8 * len - 1) : new Uint8Array(1);
    assert.ok(!verify(publicKey, tampered, sig, ctx), 'message');
    const otherCtx = ctx.length ? flip(ctx, 8 * ctx.length - 1) : new Uint8Array(1);
    assert.ok(!verify(publicKey, msg, sig, otherCtx), 'context');
    assert.ok(!verify(publicKey, msg, flip(sig, SALT_BIT + 7), ctx), 'salt');
    assert.ok(!verify(publicKey, msg, flip(sig, S2_BIT + 20), ctx), 's2');
    const end = s2End(sig);
    assert.ok(end < 5000);
    assert.ok(!verify(publicKey, msg, flip(sig, S2_BIT + end), ctx), 'the padding bit after s2');
    assert.ok(!verify(publicKey, msg, flip(sig, 8 * SIGNATURE_BYTES - 1), ctx), 'the last padding bit');
    for (const header of [0x29, 0x3a, 0x59]) {
      assert.ok(!verify(publicKey, msg, Uint8Array.of(header, ...sig.subarray(1)), ctx), 'header');
    }
    assert.ok(!verify(publicKey, msg, sig.subarray(0, SIGNATURE_BYTES - 1), ctx), 'short');
    assert.ok(!verify(publicKey, msg, Uint8Array.of(...sig, 0), ctx), 'long');
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
  assert.equal(verify(publicKey, msg, sig, 'not bytes'), false);
  assert.equal(verify(publicKey, msg, Uint8Array.of(0x39, ...new Uint8Array(SIGNATURE_BYTES - 1))), false);
  assert.throws(() => sign(secretKey.subarray(1), msg));
  assert.throws(() => sign(flip(secretKey, 8 + 3), msg)); // f changes: fG − gF = q no longer holds
  assert.throws(() => sign(secretKey, msg, new Uint8Array(256)), RangeError); // a context over 255 bytes
});

test('hashToPoint: deterministic, 512 coefficients below q, every input bit matters', () => {
  const pk = random(PUBLIC_KEY_BYTES), salt = random(SALT_BYTES), msg = random(50), ctx = random(20);
  const c = hashToPoint(pk, salt, msg, ctx);
  assert.ok(c instanceof Uint16Array);
  assert.equal(c.length, 512);
  assert.ok(c.every((x) => x < Q));
  assert.deepEqual(hashToPoint(pk, salt, msg, ctx), c);
  assert.notDeepEqual(hashToPoint(pk, salt, msg), c, 'the context left out');
  assert.notDeepEqual(hashToPoint(pk, salt, ctx, msg), c, 'the message and the context swapped');
  // One random bit in every 7-byte lane of each input, and each input's first and last bits.
  const inputs = [pk, salt, msg, ctx];
  for (let k = 0; k < 4; k++) {
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

test('keyDigest and address: eight lanes below p, the address their first 32 bytes, for any bytes', () => {
  const publicKey = random(PUBLIC_KEY_BYTES);
  for (const data of [publicKey, new Uint8Array(0), random(100)]) {
    const k = keyDigest(data), view = new DataView(k.buffer);
    assert.ok(k instanceof Uint8Array && k.length === 64);
    for (let i = 0; i < 8; i++) assert.ok(view.getBigUint64(8 * i, true) < P);
    assert.deepEqual(keyDigest(data), k);
    assert.deepEqual(address(data), k.slice(0, 32));
  }
  assert.notDeepEqual(keyDigest(flip(publicKey, 100)), keyDigest(publicKey));
});

test('the address text: 0x and 72 lowercase hex digits; read back in either case; any change refused', () => {
  const addr = address(random(PUBLIC_KEY_BYTES)), text = formatAddress(addr);
  assert.match(text, /^0x[0-9a-f]{72}$/);
  assert.deepEqual(parseAddress(text), addr);
  assert.deepEqual(parseAddress('0x' + text.slice(2).toUpperCase()), addr);
  for (let at = 2; at < 74; at++) {
    const changed = text.slice(0, at) + (text[at] === '0' ? '1' : '0') + text.slice(at + 1);
    assert.throws(() => parseAddress(changed), `digit ${at}`);
  }
  for (const other of [text.slice(2), '0X' + text.slice(2), text + '0', text.slice(0, 73), addr]) {
    assert.throws(() => parseAddress(other));
  }
  assert.throws(() => formatAddress(addr.subarray(1)), RangeError);
});
