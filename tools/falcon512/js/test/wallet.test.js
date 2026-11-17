import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, getRandomValues } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { WORDLIST } from '../bip39-english.js';
import {
  generateMnemonic, validateMnemonic, mnemonicToSeed, accountSeed, deriveAccount, _entropyToMnemonic,
} from '../wallet.js';
import { address, formatAddress } from '../falcon512.js';

// The official BIP39 vectors and keys made by the Falcon round-3 reference C; "how" in the file says
// how each part was made.
const fixture = JSON.parse(readFileSync(new URL('./fixtures/wallet.json', import.meta.url), 'utf8'));
const hex = (data) => Buffer.from(data).toString('hex');
const unhex = (text) => Uint8Array.from(Buffer.from(text, 'hex'));
const MNEMONIC = fixture.bip39[3].mnemonic;

// BIP39's own 12-word example: a valid mnemonic, but not one of 24 words.
const TWELVE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// MNEMONIC with its last word's lowest bit flipped: the entropy bits stand, the checksum breaks.
function badChecksum() {
  const words = MNEMONIC.split(' ');
  words[23] = WORDLIST[WORDLIST.indexOf(words[23]) ^ 1];
  return words.join(' ');
}

test('the wordlist: 2048 distinct words in order, 3 to 8 letters, told apart by their first four', () => {
  assert.equal(WORDLIST.length, 2048);
  assert.deepEqual([...WORDLIST].sort(), [...WORDLIST]);
  assert.ok(WORDLIST.every((word) => /^[a-z]{3,8}$/.test(word)));
  assert.equal(new Set(WORDLIST.map((word) => word.slice(0, 4))).size, 2048);
});

test('the official BIP39 vectors: each 24-word entry\'s mnemonic and seed', async () => {
  assert.equal(fixture.bip39.length, 8);
  for (const { entropy, mnemonic, seed } of fixture.bip39) {
    assert.equal(_entropyToMnemonic(unhex(entropy)), mnemonic);
    assert.equal(validateMnemonic(mnemonic), mnemonic);
    assert.equal(hex(await mnemonicToSeed(mnemonic, 'TREZOR')), seed);
  }
});

test('the checksum is SHA-256\'s first byte (node:crypto\'s)', () => {
  for (let i = 0; i < 100; i++) {
    const entropy = getRandomValues(new Uint8Array(32));
    const last = WORDLIST.indexOf(_entropyToMnemonic(entropy).split(' ')[23]);
    assert.equal(last & 0xff, createHash('sha256').update(entropy).digest()[0]);
  }
});

test('validateMnemonic: the canonical sentence, and only 24 listed words with a valid checksum', () => {
  const words = MNEMONIC.split(' ');
  assert.equal(validateMnemonic(`\n  ${words.join(' \t ').toUpperCase()}  `), MNEMONIC);
  const fullwidth = [...words[0]].map((c) => String.fromCharCode(c.charCodeAt(0) + 0xfee0)).join('');
  assert.equal(validateMnemonic([fullwidth, ...words.slice(1)].join(' ')), MNEMONIC); // NFKD
  assert.throws(() => validateMnemonic(words.slice(0, 23).join(' ')), /24 words/);
  assert.throws(() => validateMnemonic([...words, words[0]].join(' ')), /24 words/);
  assert.throws(() => validateMnemonic(TWELVE), /24 words/);
  assert.throws(() => validateMnemonic(['bitcoins', ...words.slice(1)].join(' ')), /word 1 /);
  assert.throws(() => validateMnemonic(badChecksum()), /checksum/);
  assert.throws(() => validateMnemonic(''), /24 words/);
  assert.throws(() => validateMnemonic(undefined), TypeError);
});

test('mnemonicToSeed normalizes the passphrase (NFKD)', async () => {
  const fullwidth = 'ＴＲＥＺＯＲ';
  assert.equal(hex(await mnemonicToSeed(MNEMONIC, fullwidth)), fixture.bip39[3].seed);
});

test('accountSeed is HKDF-SHA512 (an HMAC computation with node:crypto agrees)', async () => {
  // RFC 5869 with an empty salt (HMAC pads the key, as it pads HashLen zeros).
  const hkdf = (ikm, info, length) => {
    const prk = createHmac('sha512', Buffer.alloc(0)).update(ikm).digest();
    let block = Buffer.alloc(0), out = Buffer.alloc(0);
    for (let i = 1; out.length < length; i++) {
      block = createHmac('sha512', prk).update(Buffer.concat([block, info, Buffer.of(i)])).digest();
      out = Buffer.concat([out, block]);
    }
    return out.subarray(0, length);
  };
  const scheme = Buffer.from('apogee/wallet/falcon512/v1');
  for (const index of [0, 1, 2 ** 31, 2 ** 32 - 1]) {
    const root = getRandomValues(new Uint8Array(64)), u32 = Buffer.alloc(4);
    u32.writeUInt32BE(index);
    const info = Buffer.concat([Buffer.of(scheme.length), scheme, u32]);
    assert.equal(hex(await accountSeed(root, index)), hkdf(root, info, 48).toString('hex'), `index ${index}`);
  }
  for (const account of fixture.accounts) {
    const root = fixture.bip39.find((v) => v.mnemonic === account.mnemonic).seed;
    assert.equal(hex(await accountSeed(unhex(root), account.index)), account.accountSeed);
  }
  const root = new Uint8Array(64);
  for (const index of [-1, 2 ** 32, 1.5, '1']) await assert.rejects(accountSeed(root, index), RangeError);
  await assert.rejects(accountSeed(new Uint8Array(48), 0), TypeError);
});

test('deriveAccount gives the reference implementation\'s keys and their address', async () => {
  for (const account of fixture.accounts) {
    const derived = await deriveAccount(account.mnemonic, { passphrase: account.passphrase, index: account.index });
    assert.equal(hex(derived.publicKey), account.publicKey, `index ${account.index}`);
    assert.equal(hex(derived.secretKey), account.secretKey, `index ${account.index}`);
    assert.deepEqual(derived.address, address(derived.publicKey));
    assert.equal(derived.addressText, formatAddress(derived.address));
  }
});

test('recovery: the same mnemonic (any case or spacing), passphrase and index give the same account', async () => {
  const account = fixture.accounts[1];
  const typed = `  ${account.mnemonic.toUpperCase().split(' ').join('  ')}\n`;
  const recovered = await deriveAccount(typed, { passphrase: account.passphrase, index: account.index });
  assert.equal(hex(recovered.publicKey), account.publicKey);
  assert.equal(hex(recovered.secretKey), account.secretKey);
  const other = await deriveAccount(account.mnemonic, { index: account.index });
  assert.notEqual(hex(other.publicKey), account.publicKey); // a different passphrase, another wallet
});

test('deriveAccount takes only a generated mnemonic', async () => {
  await assert.rejects(deriveAccount(TWELVE), /24 words/);
  await assert.rejects(deriveAccount(badChecksum()), /checksum/);
  await assert.rejects(deriveAccount(MNEMONIC, { index: -1 }), RangeError);
});

test('generateMnemonic: 24 listed words with a valid checksum, new each time', async () => {
  const a = generateMnemonic(), b = generateMnemonic();
  assert.equal(a.split(' ').length, 24);
  assert.equal(validateMnemonic(a), a);
  assert.notEqual(a, b);
  const account = await deriveAccount(a);
  assert.equal(account.addressText.length, 74);
});
