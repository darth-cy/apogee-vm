# apogee-falcon512

Falcon-512 with Poseidon2's HashToPoint, as one zero-dependency ES module for Node.js (≥ 20) and
browsers.

This is Falcon-512 v1.2 (the NIST round-3 specification) with one change: HashToPoint maps the
key digest K, the salt, the application's context and the message to the point c with a
Poseidon2-A64-C5 sponge instead of SHAKE256(salt ‖ message). Keys, signatures, encodings, the
sampler and the acceptance rule are v1.2's. Because HashToPoint differs, it is **not interoperable
with standard Falcon-512**: a standard signature does not verify here, and a signature made here
does not verify elsewhere. The construction is specified in the apogee-vm repository's
`docs/spec/precompiles.md`, “HashToPoint” in the section “The Falcon-512 lattice check”.

## API

```js
export const PUBLIC_KEY_BYTES = 897, SECRET_KEY_BYTES = 1281, SIGNATURE_BYTES = 666, SALT_BYTES = 40;
generateKeyPair()                                 // { secretKey: Uint8Array(1281), publicKey: Uint8Array(897) }
sign(secretKey, message, context?)                // Uint8Array(666); throws on a malformed secret key or a long context
verify(publicKey, message, signature, context?)   // boolean; never throws, malformed input is false
hashToPoint(publicKey, salt, message, context?)   // Uint16Array(512), each coefficient below q = 12289
keyDigest(publicKey)                              // Uint8Array(64): K, eight lanes below p = 2^64 − 59 (any bytes)
address(publicKey)                                // Uint8Array(32): K's first 32 bytes
formatAddress(address)                            // string: "0x", 64 hex digits, 8 of checksum
parseAddress(text)                                // Uint8Array(32); throws unless text is an address
publicKeyFromSecretKey(secretKey)                 // Uint8Array(897)
```

Messages, keys, contexts and signatures are `Uint8Array`s; encode strings with `TextEncoder`.

**The context** is the application's context string, FIPS 204's and 206's convention: 0 to 255
bytes, empty by default. A signature verifies only under the context it was made under, so a key
that signs for several purposes keeps a signature for one from passing as another's. `sign` throws
on a longer context; `verify` returns false.

**The address** names a user: the first 32 bytes of K, the key digest, a sponge over the domain
`apogee/key/v1`, the scheme `falcon512-poseidon2/v1` and the 897-byte public key. Its text is `0x`,
the address in 64 lowercase hex digits, then 8 hex digits of a checksum (a sponge over the address),
74 characters. `parseAddress` reads hex digits of either case after exactly `0x`, and refuses any
other text or a checksum that does not match, so a mistyped address is caught.

## Node

```js
import { generateKeyPair, sign, verify, address, formatAddress } from 'apogee-falcon512';

const { secretKey, publicKey } = generateKeyPair();
const context = new TextEncoder().encode('example/payments/v1');
const message = new TextEncoder().encode('pay 10 to bob');
const signature = sign(secretKey, message, context);
console.log(verify(publicKey, message, signature, context)); // true
console.log(verify(publicKey, message, signature)); // false: signed under another context
console.log(formatAddress(address(publicKey))); // 0x… (74 characters)
```

## Browser

```html
<script type="module">
  import { generateKeyPair, sign, verify } from './falcon512.js';

  const { secretKey, publicKey } = generateKeyPair();
  const message = new TextEncoder().encode('pay 10 to bob');
  console.log(verify(publicKey, message, sign(secretKey, message))); // true
</script>
```

## User addresses

`recovery.js` derives user addresses from a 24-word recovery phrase (a BIP39 mnemonic); `keygen.js`
is the key generation it uses. The app's own frontend generates the phrase, derives the keys and
signs with them, so an Apogee app needs no separate signing app.

```js
generateMnemonic()                                    // string: a recovery phrase, 24 words for 32 random bytes
validateMnemonic(text)                                // string: the canonical sentence; throws unless valid
mnemonicToSeed(mnemonic, passphrase?)                 // Promise<Uint8Array(64)>: BIP39's seed
addressSeed(rootSeed, index)                          // Promise<Uint8Array(48)>: user address index's seed
deriveUserAddress(mnemonic, { passphrase?, index? })  // Promise<{ secretKey, publicKey, address, addressText }>
keygen(seed)                                          // keygen.js: { secretKey, publicKey } of a 48-byte seed
```

1. **Generate.** `generateMnemonic()` draws 32 bytes from `crypto.getRandomValues` and writes them
   as 24 words of the BIP39 English list, the last word carrying an 8-bit SHA-256 checksum: the
   recovery phrase. The frontend generates it; the user never invents one.
2. **Back up the 24 words** (and the passphrase, if one is used). Whoever has them has every user
   address they derive, and nothing else recovers one.
3. **Derive user address i.** `deriveUserAddress(mnemonic, { passphrase, index: i })` takes BIP39's
   seed (PBKDF2-HMAC-SHA512, 2048 rounds, salt `"mnemonic"` ‖ passphrase), then HKDF-SHA512 with info
   `u8(32) ‖ "apogee/user-address/falcon512/v1" ‖ u32_be(i)` for the address's 48-byte seed, then
   `keygen` for its key pair; the address is `address(publicKey)`. Indices run from 0 to 2^32 − 1.
4. **Recover.** The same words, passphrase and index give the same keys and the same user address,
   on any device. Case, spacing and Unicode compatibility forms of the words do not matter (they are
   read as NFKD, lower case, single spaces); the passphrase is taken as typed (NFKD).

**Keys come only from generated phrases.** `deriveUserAddress` refuses anything but 24 words of the
English list with a valid checksum, a 12-word BIP39 mnemonic included: a mistyped word is caught
instead of deriving another, empty user address, and no key comes from words a person picked.

**Key generation is the reference's.** `keygen(seed)` is a bit-exact port of the Falcon round-3
reference implementation's key generation (`Zf(keygen)` at logn = 9 with SHAKE256 of the seed as
its random source, keys encoded as its `crypto_sign_keypair` encodes them): the same seed gives the
same keys as the reference C, on every platform, which is what makes recovery work anywhere. It is
deterministic and synchronous, about 10 ms in Node 24.

```js
import { generateMnemonic, deriveUserAddress } from 'apogee-falcon512/recovery.js';

const phrase = generateMnemonic(); // shown once, for the user to write down
const { addressText, secretKey } = await deriveUserAddress(phrase, { index: 0 });
// Later, on any device, the words typed back in recover the same user address:
const again = await deriveUserAddress(typedWords, { index: 0 }); // again.addressText === addressText
```

In browsers, `crypto.subtle` (PBKDF2, HKDF) needs a secure context (HTTPS or localhost).

## Caveat

Signing (and key generation) uses floating point and is not constant time, so its timing can depend
on the secret key. A secret key belongs on its owner's device; do not sign with it where others can
time the signer. Verification uses only public data.

## Tests

`npm test` (`node --test`): the Poseidon2 known answer, round trips and tampering, and HashToPoint,
key digest and address properties; `test/vectors.test.js` reads the vectors shared with the Rust and
Python implementations, `../vectors.json`, the official Falcon-512 KAT among them (through the verify
core, with standard HashToPoint computed by the test). `test/keygen.test.js` holds `keygen` to keys
the reference C made (KAT seeds and user address seeds) and SHAKE256 to node:crypto's;
`test/recovery.test.js` checks the official BIP39 vectors, HKDF against an HMAC computation, and
derived user addresses against the reference's keys. `test/fixtures/recovery.json` says how each
value in it was made.
