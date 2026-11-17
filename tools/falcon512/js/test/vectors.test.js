// The shared vectors, ../../vectors.json, which the Rust and Python suites read too.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  SIGNATURE_BYTES, SALT_BYTES, verify, hashToPoint, keyDigest, address, formatAddress, parseAddress,
  _verifyWithPoint,
} from '../falcon512.js';

const Q = 12289;
const vectors = JSON.parse(readFileSync(new URL('../../vectors.json', import.meta.url), 'utf8'));
const hex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const flip = (data, bit) => {
  const out = data.slice();
  out[bit >> 3] ^= 0x80 >> (bit & 7);
  return out;
};
const SALT_BIT = 8, S2_BIT = 8 * (1 + SALT_BYTES); // the first bit of the salt, of compressed s2

// The entries of one section, at least one.
function section(name) {
  const entries = vectors[name];
  assert.ok(Array.isArray(entries) && entries.length > 0, `${name} is empty`);
  return entries;
}

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

// Standard Falcon-512's HashToPoint: SHAKE256(salt || msg) read as 16-bit big-endian samples t,
// each t < 61445 kept as t mod q, until 512.
function standardPoint(salt, msg) {
  for (let len = 1024; ; len *= 2) {
    const out = createHash('shake256', { outputLength: len }).update(salt).update(msg).digest();
    const c = [];
    for (let i = 0; i + 1 < out.length && c.length < 512; i += 2) {
      const t = (out[i] << 8) | out[i + 1];
      if (t < 61445) c.push(t % Q);
    }
    if (c.length === 512) return c;
  }
}

test('standard_kat: official Falcon-512 signatures pass the verify core', () => {
  for (const entry of section('standard_kat')) {
    const [pk, msg, sig] = [entry.pk, entry.msg, entry.sig].map(hex);
    assert.equal(sig[0], 0x39);
    const salt = sig.subarray(1, 1 + SALT_BYTES), c = standardPoint(salt, msg);
    assert.ok(_verifyWithPoint(pk, c, sig));
    assert.ok(!verify(pk, msg, sig), 'a standard signature is not one here');
    assert.ok(!_verifyWithPoint(pk, standardPoint(salt, flip(msg, 8 * msg.length - 1)), sig), 'message');
    const salted = flip(sig, SALT_BIT + 13);
    assert.ok(!_verifyWithPoint(pk, standardPoint(salted.subarray(1, 1 + SALT_BYTES), msg), salted), 'salt');
    assert.ok(!_verifyWithPoint(pk, c, flip(sig, S2_BIT + 100)), 's2');
    const end = s2End(sig);
    assert.ok(end < 5000);
    assert.ok(!_verifyWithPoint(pk, c, flip(sig, S2_BIT + end)), 'the padding bit after s2');
    assert.ok(!_verifyWithPoint(pk, c, flip(sig, 8 * SIGNATURE_BYTES - 1)), 'the last padding bit');
  }
});

test('hash_to_point: the vectors\' points', () => {
  for (const { pk, salt, context, msg, c } of section('hash_to_point')) {
    assert.deepEqual(Array.from(hashToPoint(hex(pk), hex(salt), hex(msg), hex(context))), c);
  }
});

test('key_digest: the vectors\' digests, addresses and texts', () => {
  for (const entry of section('key_digest')) {
    const pk = hex(entry.pk), text = entry.address_text;
    assert.deepEqual(keyDigest(pk), hex(entry.key_digest));
    assert.deepEqual(address(pk), hex(entry.address));
    assert.equal(formatAddress(address(pk)), text);
    assert.deepEqual(parseAddress(text), hex(entry.address));
  }
});

test('address_text: each text reads as its address, or, with none, is refused', () => {
  for (const { case: name, text, address: expected } of section('address_text')) {
    if (expected === null) assert.throws(() => parseAddress(text), name);
    else assert.deepEqual(parseAddress(text), hex(expected), name);
  }
});

test('signatures: every implementation\'s signatures verify', () => {
  for (const { signer, pk, msg, context, sig } of section('signatures')) {
    assert.ok(verify(hex(pk), hex(msg), hex(sig), hex(context)), signer);
  }
});

test('malformed: a valid signature, or its key or context, with one departure refuses', () => {
  for (const entry of section('malformed')) {
    const [pk, msg, sig, context] = [entry.pk, entry.msg, entry.sig, entry.context].map(hex);
    assert.equal(verify(pk, msg, sig, context), false, entry.case);
  }
});
