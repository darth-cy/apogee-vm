import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, getRandomValues } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SEED_BYTES, keygen, _shake256 } from '../keygen.js';
import { publicKeyFromSecretKey, sign, verify } from '../falcon512.js';

// Keys made by the Falcon round-3 reference C; fixtures/wallet.json's "how" says how each was made.
const fixture = JSON.parse(readFileSync(new URL('./fixtures/wallet.json', import.meta.url), 'utf8'));
const hex = (data) => Buffer.from(data).toString('hex');
const unhex = (text) => Uint8Array.from(Buffer.from(text, 'hex'));

test('SHAKE256 is node:crypto\'s, across block boundaries', () => {
  for (const length of [0, 1, 48, 135, 136, 137, 300]) {
    const input = getRandomValues(new Uint8Array(length));
    const expected = createHash('shake256', { outputLength: 500 }).update(input).digest('hex');
    assert.equal(hex(_shake256(input, 500)), expected, `input of ${length} bytes`);
  }
});

test('keygen gives the reference implementation\'s keys for KAT seeds', () => {
  for (const entry of fixture.kat) {
    const { publicKey, secretKey } = keygen(unhex(entry.seed48));
    assert.equal(hex(publicKey), entry.publicKey, `KAT count ${entry.count}`);
    assert.equal(hex(secretKey), entry.secretKey, `KAT count ${entry.count}`);
  }
});

test('keygen gives the reference implementation\'s keys for wallet account seeds', () => {
  for (const account of fixture.accounts) {
    const { publicKey, secretKey } = keygen(unhex(account.accountSeed));
    assert.equal(hex(publicKey), account.publicKey, `index ${account.index}`);
    assert.equal(hex(secretKey), account.secretKey, `index ${account.index}`);
  }
});

test('keygen is deterministic, and its keys sign and verify with falcon512.js', () => {
  const seed = getRandomValues(new Uint8Array(SEED_BYTES));
  const keys = keygen(seed);
  assert.deepEqual(keygen(seed.slice()), keys);
  assert.notDeepEqual(keygen(getRandomValues(new Uint8Array(SEED_BYTES))).publicKey, keys.publicKey);
  assert.deepEqual(publicKeyFromSecretKey(keys.secretKey), keys.publicKey);
  const message = new TextEncoder().encode('pay 10 to bob');
  assert.ok(verify(keys.publicKey, message, sign(keys.secretKey, message)));
});

test('keygen takes only a 48-byte Uint8Array', () => {
  assert.throws(() => keygen(new Uint8Array(47)), TypeError);
  assert.throws(() => keygen(new Uint8Array(49)), TypeError);
  assert.throws(() => keygen(Array.from(new Uint8Array(48))), TypeError);
});
